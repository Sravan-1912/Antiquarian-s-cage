"""Administrator account management (Super Admin)."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, require_permission
from app.core.database import get_db, utcnow
from app.models import Role, User, UserRole
from app.schemas.admin import (
    AdminCreatedOut,
    AdminUserOut,
    CreateAdminRequest,
    HandoverOut,
    RoleDetail,
    SetRolesRequest,
)
from app.schemas.common import Message
from app.security.permissions import PRIVILEGED_ROLE
from app.services import audit, auth, notifications, rbac, tenancy

router = APIRouter(prefix="/users", tags=["administrators"])


def _get(db: Session, ctx: AuthContext, user_id: uuid.UUID) -> User:
    u = db.get(User, user_id)
    if u is None or u.organization_id != ctx.user.organization_id:
        raise HTTPException(404, "Administrator not found")
    return u


def _active_super_admins(db: Session, org_id: uuid.UUID) -> list[User]:
    return [u for u in db.scalars(select(User).where(User.organization_id == org_id, User.status == "active"))
            if any(r.key == PRIVILEGED_ROLE for r in u.roles)]


@router.get("", response_model=list[AdminUserOut])
def list_admins(ctx: AuthContext = Depends(require_permission("users:read")), db: Session = Depends(get_db)):
    stmt = select(User).where(User.organization_id == ctx.user.organization_id).order_by(User.created_at)
    scope = tenancy.scope_admin_id(ctx)
    if scope is not None:  # an admin sees their own staff and themselves, never other admins or a super admin
        stmt = stmt.where(or_(User.owner_admin_id == scope, User.id == scope))
    users = db.scalars(stmt).all()
    return [u for u in users if any(r.key != "employee" for r in u.roles)]  # employee portal accounts live on Employees


@router.get("/roles", response_model=list[RoleDetail])
def list_roles(ctx: AuthContext = Depends(require_permission("users:read")), db: Session = Depends(get_db)):
    roles = db.scalars(select(Role).where(Role.organization_id.is_(None)).order_by(Role.name)).all()
    return [RoleDetail(key=r.key, name=r.name, description=r.description,
                       permissions=sorted(p.key for p in r.permissions)) for r in roles]


@router.post("", response_model=AdminCreatedOut, status_code=201)
def create_admin(body: CreateAdminRequest, ctx: AuthContext = Depends(require_permission("users:manage")),
                 db: Session = Depends(get_db)):
    """Create an administrator account with a temporary password. The Super Admin hands the returned password over to
    the admin, who must change it on first sign-in. The password is shown ONCE and never stored in clear."""
    org_id = ctx.user.organization_id
    if auth.find_user_by_email(db, org_id, str(body.email)):
        raise HTTPException(409, "An account with this email already exists")
    role = rbac.get_role(db, body.role)
    if role is None:
        raise HTTPException(422, "Unknown role")
    # Only a Super Admin (global) may create admins or super admins; an admin only creates staff inside its tenant.
    if not tenancy.is_global(ctx) and body.role in ("super_admin", "admin"):
        raise HTTPException(403, "Only a Super Admin can create administrator accounts")
    user = User(organization_id=org_id, owner_admin_id=tenancy.owner_for(ctx), email=str(body.email).lower(),
                full_name=body.full_name, status="active")
    db.add(user)
    db.flush()
    db.add(UserRole(user_id=user.id, role_id=role.id, granted_by=ctx.user.id))
    temp = auth.set_temporary_password(db, user)
    audit.record(db, org_id, ctx.actor, "user.created", target_type="user", target_id=user.id,
                 target_label=user.email, metadata={"role": body.role})
    db.commit()
    db.refresh(user)
    return AdminCreatedOut(user=AdminUserOut.model_validate(user), temporary_password=temp)


@router.post("/{user_id}/reset-password", response_model=HandoverOut)
def reset_password(user_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("users:manage")),
                   db: Session = Depends(get_db)):
    """Regenerate a temporary password for an admin and require a change on next sign-in — the handover step (give
    the returned password to the admin). Any active sessions for that account are signed out."""
    user = _get(db, ctx, user_id)
    if user.id == ctx.user.id:
        raise HTTPException(409, "Use Change password for your own account")
    if user.status == "disabled":
        raise HTTPException(409, "Re-enable the account before resetting its password")
    temp = auth.set_temporary_password(db, user)
    n = auth.revoke_user_sessions(db, user.id, "password_reset")
    audit.record(db, user.organization_id, ctx.actor, "user.password_reset", target_type="user", target_id=user.id,
                 target_label=user.email, metadata={"sessions_revoked": n})
    db.commit()
    return HandoverOut(user_id=user.id, email=user.email, temporary_password=temp)


@router.put("/{user_id}/roles", response_model=AdminUserOut)
def set_roles(user_id: uuid.UUID, body: SetRolesRequest,
              ctx: AuthContext = Depends(require_permission("users:manage")), db: Session = Depends(get_db)):
    user = _get(db, ctx, user_id)
    before = sorted(r.key for r in user.roles)
    after = sorted(set(body.roles))
    if PRIVILEGED_ROLE in before and PRIVILEGED_ROLE not in after:
        if len(_active_super_admins(db, user.organization_id)) <= 1:
            raise HTTPException(409, "At least one active Super Admin must remain")
    db.execute(delete(UserRole).where(UserRole.user_id == user.id))
    for key in after:
        role = rbac.get_role(db, key)
        if role is None:
            raise HTTPException(500, "Role catalogue is incomplete")
        db.add(UserRole(user_id=user.id, role_id=role.id, granted_by=ctx.user.id))
    # Role changes take effect immediately; force re-authentication so no session keeps stale context.
    revoked = auth.revoke_user_sessions(db, user.id, "roles_changed") if user.id != ctx.user.id else 0
    audit.record(db, user.organization_id, ctx.actor, "user.roles_changed", target_type="user", target_id=user.id,
                 target_label=user.email, metadata={"before": before, "after": after, "sessions_revoked": revoked})
    db.commit()
    db.expire(user)
    return db.get(User, user.id)


@router.post("/{user_id}/disable", response_model=AdminUserOut)
def disable_admin(user_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("users:manage")),
                  db: Session = Depends(get_db)):
    user = _get(db, ctx, user_id)
    if user.id == ctx.user.id:
        raise HTTPException(409, "You cannot disable your own account")
    if any(r.key == PRIVILEGED_ROLE for r in user.roles) and len(_active_super_admins(db, user.organization_id)) <= 1:
        raise HTTPException(409, "At least one active Super Admin must remain")
    user.status = "disabled"
    n = auth.revoke_user_sessions(db, user.id, "account_disabled")
    audit.record(db, user.organization_id, ctx.actor, "user.disabled", target_type="user", target_id=user.id,
                 target_label=user.email, metadata={"sessions_revoked": n})
    db.commit()
    return user


@router.post("/{user_id}/enable", response_model=AdminUserOut)
def enable_admin(user_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("users:manage")),
                 db: Session = Depends(get_db)):
    user = _get(db, ctx, user_id)
    if user.status != "disabled":
        raise HTTPException(409, "Only disabled accounts can be re-enabled")
    user.status = "active"
    user.failed_login_count = 0
    user.locked_until = None
    audit.record(db, user.organization_id, ctx.actor, "user.enabled", target_type="user", target_id=user.id,
                 target_label=user.email)
    db.commit()
    return user


@router.post("/{user_id}/unlock", response_model=AdminUserOut)
def unlock_admin(user_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("users:manage")),
                 db: Session = Depends(get_db)):
    user = _get(db, ctx, user_id)
    user.locked_until = None
    user.failed_login_count = 0
    audit.record(db, user.organization_id, ctx.actor, "user.unlocked", target_type="user", target_id=user.id,
                 target_label=user.email)
    db.commit()
    return user


@router.post("/{user_id}/revoke-sessions", response_model=Message)
def revoke_admin_sessions(user_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("users:manage")),
                          db: Session = Depends(get_db)):
    user = _get(db, ctx, user_id)
    except_id = ctx.session.id if user.id == ctx.user.id else None
    n = auth.revoke_user_sessions(db, user.id, "admin_revoked", except_id=except_id)
    audit.record(db, user.organization_id, ctx.actor, "user.sessions_revoked", target_type="user",
                 target_id=user.id, target_label=user.email, metadata={"count": n})
    if user.id != ctx.user.id:
        notifications.notify_users(db, user.organization_id, [user], kind="security.sessions_revoked",
                                   severity="medium", title="Your sessions were revoked",
                                   body=f"{ctx.user.full_name} signed you out of all sessions at {utcnow():%Y-%m-%d %H:%M} UTC.")
    db.commit()
    return Message(detail=f"{n} session(s) revoked")
