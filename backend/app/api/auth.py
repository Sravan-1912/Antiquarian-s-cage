from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    AuthContext,
    client_info,
    current_context,
    rate_limit,
)
from app.core.config import get_settings
from app.core.database import get_db, utcnow
from app.models import AuthenticationEvent, Organization, UserSession
from app.schemas import auth as s
from app.schemas.common import Message
from app.services import audit, auth
from app.services.auth import AuthError

router = APIRouter(prefix="/auth", tags=["auth"])


def _raise(e: AuthError) -> None:
    raise HTTPException(status_code=e.status, detail=e.message)


def _set_cookies(resp: Response, token: str, csrf: str) -> None:
    st = get_settings()
    max_age = st.session_absolute_timeout_hours * 3600
    resp.set_cookie(SESSION_COOKIE, token, max_age=max_age, httponly=True, secure=st.cookie_secure,
                    samesite="strict", path="/")
    resp.set_cookie(CSRF_COOKIE, csrf, max_age=max_age, httponly=False, secure=st.cookie_secure,
                    samesite="strict", path="/")


def _clear_cookies(resp: Response) -> None:
    resp.delete_cookie(SESSION_COOKIE, path="/")
    resp.delete_cookie(CSRF_COOKIE, path="/")


@router.get("/bootstrap-status", response_model=s.BootstrapStatus)
def bootstrap_status(db: Session = Depends(get_db)):
    return s.BootstrapStatus(needs_setup=auth.needs_setup(db))


@router.post("/register", response_model=s.RegisterResponse, status_code=201,
             dependencies=[Depends(rate_limit("register", 5))])
def register(body: s.RegisterRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    """First-run setup: create the organisation and its first Super Admin with a password, and sign them in. Closed
    once any user exists; further organisations and admins are created by a Super Admin."""
    try:
        result = auth.register_first_admin(db, org_name=body.organization_name, full_name=body.full_name,
                                           email_addr=str(body.email), password=body.password,
                                           client=client_info(request))
    except auth.PasswordPolicyError as e:
        raise HTTPException(422, str(e))
    except AuthError as e:
        _raise(e)
    _set_cookies(response, result.session_token, result.csrf_token)
    return s.RegisterResponse(detail="Organisation created. You are signed in.")


@router.post("/login", response_model=s.LoginResponse, dependencies=[Depends(rate_limit("login", 10))])
def login(body: s.LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    """Password sign-in. On success a session cookie is set; `must_change_password` tells the client to force a
    password change (temporary password from a Super Admin handover)."""
    try:
        result = auth.login_with_password(db, str(body.email), body.password, client_info(request))
    except AuthError as e:
        _raise(e)
    _set_cookies(response, result.session_token, result.csrf_token)
    return s.LoginResponse(must_change_password=result.must_change_password)


@router.post("/password", response_model=Message)
def change_password(body: s.ChangePasswordRequest, ctx: AuthContext = Depends(current_context),
                    db: Session = Depends(get_db)):
    """Change your own password (also used to clear a forced change after a handover). Signs out other sessions."""
    try:
        auth.change_password(db, ctx.user, body.current_password, body.new_password, ctx.client,
                             keep_session_id=ctx.session.id)
    except auth.PasswordPolicyError as e:
        raise HTTPException(422, str(e))
    except AuthError as e:
        _raise(e)
    return Message(detail="Password changed")


@router.post("/logout", response_model=Message)
def logout(response: Response, ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    auth.logout(db, ctx.session, ctx.user, ctx.client)
    _clear_cookies(response)
    return Message(detail="Signed out")


@router.get("/me", response_model=s.MeResponse)
def me(ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    u = ctx.user
    org = db.get(Organization, u.organization_id)
    return s.MeResponse(
        id=u.id, email=u.email, full_name=u.full_name, organization_id=u.organization_id,
        organization_name=org.name if org else "", roles=[s.RoleOut.model_validate(r) for r in u.roles],
        permissions=sorted(ctx.permissions),
        email_verified=u.email_verified_at is not None, last_login_at=u.last_login_at,
        must_change_password=u.must_change_password,
    )


@router.get("/sessions", response_model=list[s.SessionOut])
def list_sessions(ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    rows = db.scalars(
        select(UserSession)
        .where(UserSession.user_id == ctx.user.id, UserSession.revoked_at.is_(None),
               UserSession.expires_at > utcnow())
        .order_by(UserSession.last_seen_at.desc())
    ).all()
    out = []
    for r in rows:
        item = s.SessionOut.model_validate(r)
        item.current = r.id == ctx.session.id
        out.append(item)
    return out


@router.delete("/sessions/{session_id}", response_model=Message)
def revoke_session(session_id: uuid.UUID, ctx: AuthContext = Depends(current_context),
                   db: Session = Depends(get_db)):
    sess = db.get(UserSession, session_id)
    if sess is None or sess.user_id != ctx.user.id:
        raise HTTPException(404, "Session not found")
    sess.revoked_at = utcnow()
    sess.revoked_reason = "user_revoked"
    audit.record(db, ctx.user.organization_id, ctx.actor, "auth.session_revoked", target_type="session",
                 target_id=sess.id, target_label=ctx.user.email)
    db.commit()
    return Message(detail="Session revoked")


@router.post("/sessions/revoke-others", response_model=Message)
def revoke_others(ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    n = auth.revoke_user_sessions(db, ctx.user.id, "user_revoked_others", except_id=ctx.session.id)
    audit.record(db, ctx.user.organization_id, ctx.actor, "auth.sessions_revoked", target_type="user",
                 target_id=ctx.user.id, target_label=ctx.user.email, metadata={"count": n})
    db.commit()
    return Message(detail=f"{n} other session(s) revoked")


@router.get("/login-history", response_model=list[s.AuthEventOut])
def login_history(ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    return db.scalars(
        select(AuthenticationEvent)
        .where(AuthenticationEvent.user_id == ctx.user.id)
        .order_by(AuthenticationEvent.created_at.desc())
        .limit(50)
    ).all()
