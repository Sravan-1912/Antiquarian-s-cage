"""Organization management — a Super Admin creates new organizations, each with its own first Super Admin."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, require_permission
from app.core.database import get_db
from app.models import Organization, User, UserRole
from app.schemas.admin import CreateOrganizationRequest, OrganizationCreatedOut
from app.services import audit, auth, rbac, tenancy

router = APIRouter(prefix="/organizations", tags=["organizations"])


def _unique_slug(db: Session, name: str) -> str:
    base = auth.slugify(name)
    slug = base
    i = 2
    while db.scalar(select(func.count()).select_from(Organization).where(Organization.slug == slug)):
        slug = f"{base}-{i}"[:64]
        i += 1
    return slug


@router.post("", response_model=OrganizationCreatedOut, status_code=201)
def create_organization(body: CreateOrganizationRequest,
                        ctx: AuthContext = Depends(require_permission("users:manage")),
                        db: Session = Depends(get_db)):
    """Create a new organization and its first Super Admin with a temporary password. Only a (global) Super Admin may
    do this. The returned password is shown ONCE, for handover to that organization's Super Admin."""
    if not tenancy.is_global(ctx):
        raise HTTPException(403, "Only a Super Admin can create organizations")
    rbac.sync_rbac(db)
    org = Organization(name=body.organization_name.strip(), slug=_unique_slug(db, body.organization_name), settings={})
    db.add(org)
    db.flush()
    user = User(organization_id=org.id, email=str(body.super_admin_email).lower(),
                full_name=body.super_admin_full_name, status="active")
    db.add(user)
    db.flush()
    role = rbac.get_role(db, "super_admin")
    if role is None:
        raise HTTPException(500, "Role catalogue is incomplete")
    db.add(UserRole(user_id=user.id, role_id=role.id, granted_by=ctx.user.id))
    temp = auth.set_temporary_password(db, user)
    audit.record(db, ctx.user.organization_id, ctx.actor, "org.created", target_type="organization",
                 target_id=org.id, target_label=org.name)
    audit.record(db, org.id, ctx.actor, "org.bootstrap", target_type="user", target_id=user.id,
                 target_label=user.email, metadata={"created_by": str(ctx.user.id)})
    db.commit()
    return OrganizationCreatedOut(organization_id=org.id, organization_name=org.name,
                                  super_admin_email=user.email, temporary_password=temp)
