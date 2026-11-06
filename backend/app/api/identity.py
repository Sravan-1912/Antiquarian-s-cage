"""Passkeys, applications (SSO) and the employee self-service workspace."""
from __future__ import annotations

import secrets
import uuid
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.auth import _set_cookies
from app.api.deps import AuthContext, client_info, current_context, rate_limit, require_permission
from app.core.database import get_db, utcnow
from app.models import (
    Application, ApplicationAssignment, AuthenticationEvent, Device, Employee, User, WebAuthnCredential,
)
from app.security.tokens import hash_token
from app.services import audit, devices, passkeys
from app.services.auth import AuthError

router = APIRouter(tags=["identity"])


def _raise(e: AuthError):
    raise HTTPException(e.status, e.message)


# =============================================================================================== passkeys
class PasskeyVerify(BaseModel):
    challenge_id: uuid.UUID
    credential: dict
    name: str = Field(default="Passkey", min_length=1, max_length=64)


@router.post("/auth/passkeys/register/options")
def passkey_register_options(ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    cid, opts = passkeys.registration_options(db, ctx.user)
    return {"challenge_id": str(cid), "options": opts}


@router.post("/auth/passkeys/register/verify")
def passkey_register(body: PasskeyVerify, ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    try:
        cred = passkeys.register(db, ctx.user, body.challenge_id, body.credential, body.name.strip(), ctx.client)
    except AuthError as e:
        _raise(e)
    return passkeys.describe(cred)


@router.get("/auth/passkeys")
def list_passkeys(ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    return [passkeys.describe(c) for c in passkeys.active_credentials(db, ctx.user.id)]


@router.delete("/auth/passkeys/{cid}")
def revoke_passkey(cid: uuid.UUID, ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    c = db.get(WebAuthnCredential, cid)
    if c is None or c.user_id != ctx.user.id or c.revoked_at:
        raise HTTPException(404, "Passkey not found")
    passkeys.revoke(db, c, ctx.actor, ctx.user.id)
    return {"revoked": True}


@router.post("/auth/passkeys/login/options", dependencies=[Depends(rate_limit("passkey-login", 20))])
def passkey_login_options(db: Session = Depends(get_db)):
    cid, opts = passkeys.authentication_options(db)
    return {"challenge_id": str(cid), "options": opts}


class PasskeyLogin(BaseModel):
    challenge_id: uuid.UUID
    credential: dict


@router.post("/auth/passkeys/login/verify", dependencies=[Depends(rate_limit("passkey-login", 20))])
def passkey_login(body: PasskeyLogin, request: Request, response: Response, db: Session = Depends(get_db)):
    try:
        res = passkeys.authenticate(db, body.challenge_id, body.credential, client_info(request))
    except AuthError as e:
        _raise(e)
    _set_cookies(response, res.session_token, res.csrf_token)
    return {"mfa_required": False}


@router.get("/users/{user_id}/passkeys")
def admin_list_passkeys(user_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("users:manage")),
                        db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if u is None or u.organization_id != ctx.user.organization_id:
        raise HTTPException(404, "User not found")
    return [passkeys.describe(c) for c in passkeys.active_credentials(db, u.id)]


@router.delete("/users/{user_id}/passkeys/{cid}")
def admin_revoke_passkey(user_id: uuid.UUID, cid: uuid.UUID, ctx: AuthContext = Depends(require_permission("users:manage")),
                         db: Session = Depends(get_db)):
    c = db.get(WebAuthnCredential, cid)
    u = db.get(User, user_id)
    if c is None or u is None or c.user_id != u.id or u.organization_id != ctx.user.organization_id or c.revoked_at:
        raise HTTPException(404, "Passkey not found")
    passkeys.revoke(db, c, ctx.actor, ctx.user.id)
    return {"revoked": True}


# =============================================================================================== applications
APPS_READ = require_permission("applications:read")
APPS_MANAGE = require_permission("applications:manage")


def _valid_redirect(u: str) -> str:
    p = urlparse(u)
    if p.fragment or not p.netloc or p.username or p.password:
        raise ValueError(f"invalid redirect URI: {u}")
    if p.scheme == "https" or (p.scheme == "http" and p.hostname in ("localhost", "127.0.0.1")):
        return u
    raise ValueError(f"redirect URIs must use https (http only for localhost): {u}")


class AppCreate(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    description: str = Field(default="", max_length=1000)
    client_type: str = Field(pattern="^(confidential|public)$")
    redirect_uris: list[str] = Field(min_length=1, max_length=10)
    launch_url: str | None = Field(default=None, max_length=512)
    mfa_required: bool = False

    @field_validator("redirect_uris")
    @classmethod
    def _r(cls, v):
        return [_valid_redirect(x.strip()) for x in v]

    @field_validator("launch_url")
    @classmethod
    def _launch(cls, v):
        return _valid_redirect(v) if v else v


class AppUpdate(BaseModel):
    description: str | None = Field(default=None, max_length=1000)
    redirect_uris: list[str] | None = Field(default=None, min_length=1, max_length=10)
    launch_url: str | None = Field(default=None, max_length=512)
    mfa_required: bool | None = None
    status: str | None = Field(default=None, pattern="^(active|disabled)$")

    @field_validator("redirect_uris")
    @classmethod
    def _r(cls, v):
        return [_valid_redirect(x.strip()) for x in v] if v else v


def _app_out(db: Session, a: Application, secret: str | None = None) -> dict:
    n = db.scalar(select(func.count()).select_from(ApplicationAssignment).where(
        ApplicationAssignment.application_id == a.id, ApplicationAssignment.revoked_at.is_(None))) or 0
    out = {"id": str(a.id), "name": a.name, "description": a.description, "protocol": a.protocol,
           "client_id": a.client_id, "client_type": a.client_type, "redirect_uris": (a.redirect_uris or {}).get("uris", []),
           "launch_url": a.launch_url, "mfa_required": a.mfa_required, "status": a.status,
           "verified_at": a.verified_at, "created_at": a.created_at, "assigned_employees": n,
           "integration": "verified" if a.verified_at else "configured — not yet verified by a real sign-in"}
    if secret:
        out["client_secret"] = secret  # shown once
    return out


def _app(db: Session, ctx: AuthContext, aid: uuid.UUID) -> Application:
    a = db.get(Application, aid)
    if a is None or a.organization_id != ctx.user.organization_id:
        raise HTTPException(404, "Application not found")
    return a


@router.get("/applications")
def list_apps(ctx: AuthContext = Depends(APPS_READ), db: Session = Depends(get_db)):
    return [_app_out(db, a) for a in db.scalars(select(Application).where(
        Application.organization_id == ctx.user.organization_id).order_by(Application.name))]


@router.post("/applications", status_code=201)
def create_app(body: AppCreate, ctx: AuthContext = Depends(APPS_MANAGE), db: Session = Depends(get_db)):
    if db.scalar(select(Application.id).where(Application.organization_id == ctx.user.organization_id,
                                              Application.name == body.name.strip())):
        raise HTTPException(409, "An application with this name exists")
    secret = secrets.token_urlsafe(32) if body.client_type == "confidential" else None
    a = Application(organization_id=ctx.user.organization_id, name=body.name.strip(), description=body.description,
                    client_id="cage-" + secrets.token_hex(12), client_type=body.client_type,
                    client_secret_hash=hash_token(secret) if secret else None,
                    redirect_uris={"uris": body.redirect_uris}, launch_url=body.launch_url,
                    mfa_required=body.mfa_required, created_by=ctx.user.id)
    db.add(a)
    db.flush()
    audit.record(db, a.organization_id, ctx.actor, "application.registered", target_type="application", target_id=a.id,
                 target_label=a.name, metadata={"client_type": a.client_type, "redirect_uris": body.redirect_uris,
                                                "mfa_required": a.mfa_required})
    db.commit()
    return _app_out(db, a, secret)


@router.get("/applications/{aid}")
def get_app(aid: uuid.UUID, ctx: AuthContext = Depends(APPS_READ), db: Session = Depends(get_db)):
    return _app_out(db, _app(db, ctx, aid))


@router.patch("/applications/{aid}")
def update_app(aid: uuid.UUID, body: AppUpdate, ctx: AuthContext = Depends(APPS_MANAGE), db: Session = Depends(get_db)):
    a = _app(db, ctx, aid)
    changes = body.model_dump(exclude_unset=True)
    if "redirect_uris" in changes:
        changes["redirect_uris"] = {"uris": changes["redirect_uris"]}
    for k, v in changes.items():
        setattr(a, k, v)
    if "redirect_uris" in changes:
        a.verified_at = None  # integration must be re-proven with the new configuration
    audit.record(db, a.organization_id, ctx.actor, "application.updated", target_type="application", target_id=a.id,
                 target_label=a.name, metadata={"changes": {k: str(v) for k, v in changes.items()}})
    db.commit()
    return _app_out(db, a)


@router.post("/applications/{aid}/rotate-secret")
def rotate_secret(aid: uuid.UUID, ctx: AuthContext = Depends(APPS_MANAGE), db: Session = Depends(get_db)):
    a = _app(db, ctx, aid)
    if a.client_type != "confidential":
        raise HTTPException(409, "Public clients have no secret")
    secret = secrets.token_urlsafe(32)
    a.client_secret_hash = hash_token(secret)
    audit.record(db, a.organization_id, ctx.actor, "application.secret_rotated", target_type="application",
                 target_id=a.id, target_label=a.name)
    db.commit()
    return _app_out(db, a, secret)


class AssignEmployees(BaseModel):
    employee_ids: list[uuid.UUID] = Field(min_length=1, max_length=500)


@router.get("/applications/{aid}/assignments")
def app_assignments(aid: uuid.UUID, ctx: AuthContext = Depends(APPS_READ), db: Session = Depends(get_db)):
    _app(db, ctx, aid)
    rows = db.execute(select(ApplicationAssignment, Employee).join(Employee, Employee.id == ApplicationAssignment.employee_id)
                      .where(ApplicationAssignment.application_id == aid, ApplicationAssignment.revoked_at.is_(None))
                      .order_by(Employee.full_name)).all()
    return [{"id": str(x.id), "employee_id": str(e.id), "employee_name": e.full_name, "email": e.email,
             "employee_status": e.status, "has_portal_account": e.user_id is not None, "granted_at": x.granted_at}
            for x, e in rows]


@router.post("/applications/{aid}/assignments")
def assign_app(aid: uuid.UUID, body: AssignEmployees, ctx: AuthContext = Depends(APPS_MANAGE),
               db: Session = Depends(get_db)):
    a = _app(db, ctx, aid)
    added = []
    for eid in dict.fromkeys(body.employee_ids):
        e = db.get(Employee, eid)
        if e is None or e.organization_id != a.organization_id:
            raise HTTPException(404, f"Employee {eid} not found")
        if e.status != "active":
            raise HTTPException(409, f"{e.full_name} is {e.status}; only active employees can be granted access")
        if db.scalar(select(ApplicationAssignment.id).where(ApplicationAssignment.application_id == a.id,
                                                            ApplicationAssignment.employee_id == e.id,
                                                            ApplicationAssignment.revoked_at.is_(None))):
            continue
        db.add(ApplicationAssignment(application_id=a.id, employee_id=e.id, granted_by=ctx.user.id))
        added.append(e.email)
    audit.record(db, a.organization_id, ctx.actor, "application.access_granted", target_type="application",
                 target_id=a.id, target_label=a.name, metadata={"employees": added})
    db.commit()
    return {"granted": len(added)}


@router.delete("/applications/{aid}/assignments/{assignment_id}")
def revoke_app(aid: uuid.UUID, assignment_id: uuid.UUID, ctx: AuthContext = Depends(APPS_MANAGE),
               db: Session = Depends(get_db)):
    a = _app(db, ctx, aid)
    x = db.get(ApplicationAssignment, assignment_id)
    if x is None or x.application_id != a.id or x.revoked_at:
        raise HTTPException(404, "Assignment not found")
    x.revoked_at, x.revoked_by, x.revoke_reason = utcnow(), ctx.user.id, "administrator"
    e = db.get(Employee, x.employee_id)
    audit.record(db, a.organization_id, ctx.actor, "application.access_revoked", target_type="application",
                 target_id=a.id, target_label=a.name, metadata={"employee": e.email if e else None})
    db.commit()
    return {"revoked": True}


@router.get("/applications/{aid}/events")
def app_events(aid: uuid.UUID, limit: int = Query(50, ge=1, le=200), ctx: AuthContext = Depends(APPS_READ),
               db: Session = Depends(get_db)):
    _app(db, ctx, aid)
    return [{"id": str(ev.id), "event_type": ev.event_type, "success": ev.success, "reason": ev.reason,
             "email": ev.email_attempted, "ip": ev.ip, "created_at": ev.created_at}
            for ev in db.scalars(select(AuthenticationEvent).where(AuthenticationEvent.application_id == aid)
                                 .order_by(AuthenticationEvent.created_at.desc()).limit(limit))]


# =============================================================================================== workspace
@router.get("/me/workspace")
def workspace(ctx: AuthContext = Depends(require_permission("self:read")), db: Session = Depends(get_db)):
    emp = db.scalar(select(Employee).where(Employee.user_id == ctx.user.id))
    if emp is None:
        return {"employee": None, "devices": [], "applications": []}
    devs = db.scalars(select(Device).where(Device.employee_id == emp.id, Device.status.in_(("active", "suspended")))
                      .order_by(Device.display_name)).all()
    apps = db.scalars(select(Application).join(ApplicationAssignment, ApplicationAssignment.application_id == Application.id)
                      .where(ApplicationAssignment.employee_id == emp.id, ApplicationAssignment.revoked_at.is_(None),
                             Application.status == "active").order_by(Application.name)).all()
    return {
        "employee": {"full_name": emp.full_name, "email": emp.email, "department": emp.department,
                     "job_title": emp.job_title, "employee_number": emp.employee_number, "status": emp.status},
        "devices": [{"id": str(d.id), "name": d.display_name, "os": d.os_name, "status": d.status,
                     "connectivity": devices.connectivity(d), "compliance_state": d.compliance_state,
                     "last_heartbeat_at": d.last_heartbeat_at} for d in devs],
        "applications": [{"id": str(a.id), "name": a.name, "description": a.description, "launch_url": a.launch_url,
                          "mfa_required": a.mfa_required} for a in apps],
    }


@router.get("/employees/{emp_id}/applications")
def employee_applications(emp_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("employees:read")),
                          db: Session = Depends(get_db)):
    e = db.get(Employee, emp_id)
    if e is None or e.organization_id != ctx.user.organization_id:
        raise HTTPException(404, "Employee not found")
    rows = db.execute(select(ApplicationAssignment, Application)
                      .join(Application, Application.id == ApplicationAssignment.application_id)
                      .where(ApplicationAssignment.employee_id == e.id)
                      .order_by(ApplicationAssignment.granted_at.desc())).all()
    return [{"assignment_id": str(x.id), "application_id": str(a.id), "name": a.name, "granted_at": x.granted_at,
             "revoked_at": x.revoked_at, "revoke_reason": x.revoke_reason} for x, a in rows]
