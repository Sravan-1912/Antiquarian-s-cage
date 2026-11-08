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
    pending_mfa_context,
    rate_limit,
)
from app.core.config import get_settings
from app.core.database import get_db, utcnow
from app.models import AuthenticationEvent, Organization, UserSession
from app.schemas import auth as s
from app.schemas.common import Message
from app.services import audit, auth
from app.services.auth import AuthError
from app.services.email import EmailDeliveryError

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
def register(body: s.RegisterRequest, request: Request, db: Session = Depends(get_db)):
    """Creates the first Super Admin. Closed once any user exists; further admins are invited.

    Passwordless (no password in the body): returns a single-use enrol token the browser uses to register the first
    passkey via /auth/enroll/*. Legacy password path kept during the passkey-only migration.
    """
    try:
        _, enroll = auth.register_first_admin(db, org_name=body.organization_name, full_name=body.full_name,
                                              email_addr=str(body.email), password=body.password,
                                              client=client_info(request))
    except AuthError as e:
        _raise(e)
    except EmailDeliveryError:
        raise HTTPException(502, "Account created, but the verification email could not be sent.")
    if enroll is not None:
        return s.RegisterResponse(detail="Organisation created. Register your passkey to finish.", enroll_token=enroll)
    return s.RegisterResponse(detail="Account created. Check your email to verify your address before signing in.")


@router.post("/enroll/options", dependencies=[Depends(rate_limit("enroll", 20))])
def enroll_options(body: s.EnrollOptionsRequest, db: Session = Depends(get_db)):
    """Registration-ceremony options for a passwordless enrol/invite/recovery token (no session needed)."""
    from app.services import passkeys
    try:
        user, _purpose = auth.peek_enroll_user(db, body.token)
    except AuthError as e:
        _raise(e)
    challenge_id, options = passkeys.registration_options(db, user)
    return {"challenge_id": str(challenge_id), "options": options}


@router.post("/enroll/verify", response_model=s.LoginResponse, dependencies=[Depends(rate_limit("enroll", 20))])
def enroll_verify(body: s.EnrollVerifyRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    """Register the passkey, activate the account, and sign in. Replaces password set-up for bootstrap/invite/recovery."""
    from app.services import passkeys
    client = client_info(request)
    try:
        user, purpose = auth.peek_enroll_user(db, body.token)
        if purpose == "passkey_recovery":
            passkeys.revoke_all(db, user, auth.Actor("user", user.id, user.email, client.ip))
        passkeys.register(db, user, body.challenge_id, body.credential, body.name, client)  # owns WebAuthn verify
        result = auth.complete_enroll(db, body.token, user, purpose, client)
    except AuthError as e:
        _raise(e)
    _set_cookies(response, result.session_token, result.csrf_token)
    return s.LoginResponse(mfa_required=False)


@router.post("/verify-email", response_model=Message, dependencies=[Depends(rate_limit("token", 20))])
def verify_email(body: s.TokenRequest, request: Request, db: Session = Depends(get_db)):
    try:
        auth.verify_email(db, body.token, client_info(request))
    except AuthError as e:
        _raise(e)
    return Message(detail="Email verified. You can now sign in.")


@router.post("/login", response_model=s.LoginResponse)
def login(body: s.LoginRequest, request: Request, response: Response, db: Session = Depends(get_db),
          _rl=Depends(rate_limit("login", get_settings().login_rate_limit_per_minute))):
    try:
        result = auth.login(db, str(body.email), body.password, client_info(request))
    except AuthError as e:
        _raise(e)
    _set_cookies(response, result.session_token, result.csrf_token)
    return s.LoginResponse(mfa_required=result.mfa_required)


@router.post("/mfa/verify", response_model=Message, dependencies=[Depends(rate_limit("mfa", 10))])
def mfa_verify(body: s.MfaCode, ctx: AuthContext = Depends(pending_mfa_context), db: Session = Depends(get_db)):
    try:
        auth.verify_mfa_login(db, ctx.session, ctx.user, body.code, ctx.client)
    except AuthError as e:
        _raise(e)
    return Message(detail="Verified")


@router.post("/logout", response_model=Message)
def logout(response: Response, ctx: AuthContext = Depends(pending_mfa_context), db: Session = Depends(get_db)):
    auth.logout(db, ctx.session, ctx.user, ctx.client)
    _clear_cookies(response)
    return Message(detail="Signed out")


@router.post("/password/forgot", response_model=Message, status_code=202,
             dependencies=[Depends(rate_limit("forgot", 5))])
def forgot_password(body: s.ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
    try:
        auth.request_password_reset(db, str(body.email), client_info(request))
    except EmailDeliveryError:
        pass  # Do not reveal account existence via delivery errors; failure is logged server-side.
    return Message(detail="If an account exists for that address, a reset link has been sent.")


@router.post("/password/reset", response_model=Message, dependencies=[Depends(rate_limit("token", 20))])
def reset_password(body: s.ResetPasswordRequest, request: Request, db: Session = Depends(get_db)):
    try:
        auth.reset_password(db, body.token, body.new_password, client_info(request))
    except AuthError as e:
        _raise(e)
    return Message(detail="Password updated. Sign in with your new password.")


@router.post("/invite/accept", response_model=Message, dependencies=[Depends(rate_limit("token", 20))])
def accept_invite(body: s.AcceptInviteRequest, request: Request, db: Session = Depends(get_db)):
    try:
        auth.accept_invite(db, body.token, body.password, client_info(request))
    except AuthError as e:
        _raise(e)
    return Message(detail="Account activated. You can now sign in.")


@router.post("/password/change", response_model=Message)
def change_password(body: s.ChangePasswordRequest, ctx: AuthContext = Depends(current_context),
                    db: Session = Depends(get_db)):
    try:
        auth.change_password(db, ctx.user, ctx.session, body.current_password, body.new_password, ctx.client)
    except AuthError as e:
        _raise(e)
    return Message(detail="Password changed. Other sessions were signed out.")


@router.get("/me", response_model=s.MeResponse)
def me(ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    u = ctx.user
    org = db.get(Organization, u.organization_id)
    return s.MeResponse(
        id=u.id, email=u.email, full_name=u.full_name, organization_id=u.organization_id,
        organization_name=org.name if org else "", roles=[s.RoleOut.model_validate(r) for r in u.roles],
        permissions=sorted(ctx.permissions), mfa_enabled=u.mfa_enabled,
        email_verified=u.email_verified_at is not None, last_login_at=u.last_login_at,
    )


@router.post("/mfa/setup", response_model=s.MfaSetupResponse)
def mfa_setup(ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    try:
        secret, uri = auth.begin_mfa_setup(db, ctx.user)
    except AuthError as e:
        _raise(e)
    return s.MfaSetupResponse(secret=secret, otpauth_uri=uri)


@router.post("/mfa/enable", response_model=Message)
def mfa_enable(body: s.MfaCode, ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    try:
        auth.confirm_mfa_setup(db, ctx.user, body.code, ctx.client)
    except AuthError as e:
        _raise(e)
    return Message(detail="Multi-factor authentication enabled.")


@router.post("/mfa/disable", response_model=Message)
def mfa_disable(body: s.MfaDisableRequest, ctx: AuthContext = Depends(current_context),
                db: Session = Depends(get_db)):
    try:
        auth.disable_mfa(db, ctx.user, body.password, body.code, ctx.client)
    except AuthError as e:
        _raise(e)
    return Message(detail="Multi-factor authentication disabled.")


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
