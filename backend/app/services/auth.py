"""Authentication: bootstrap registration, login, lockout, sessions, MFA, verification and password reset."""
from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utcnow
from app.models import AuthenticationEvent, AuthToken, Organization, User, UserRole, UserSession
from app.security import crypto, totp
from app.security.passwords import hash_password, needs_rehash, password_problems, verify_password
from app.security.tokens import hash_token, new_token
from app.services import audit, email, notifications, rbac
from app.services.audit import Actor

log = logging.getLogger(__name__)


class AuthError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


@dataclass
class ClientInfo:
    ip: str | None
    user_agent: str | None


# --------------------------------------------------------------------------------------------- helpers
def default_org(db: Session) -> Organization | None:
    return db.scalar(select(Organization).order_by(Organization.created_at).limit(1))


def find_user_by_email(db: Session, org_id: uuid.UUID, email_addr: str) -> User | None:
    return db.scalar(
        select(User).where(User.organization_id == org_id, func.lower(User.email) == email_addr.strip().lower())
    )


def _event(db: Session, org_id, user: User | None, event_type: str, success: bool, client: ClientInfo,
           reason: str | None = None, email_attempted: str | None = None) -> None:
    db.add(
        AuthenticationEvent(
            organization_id=org_id,
            user_id=user.id if user else None,
            email_attempted=(email_attempted or (user.email if user else None) or "")[:320],
            event_type=event_type,
            success=success,
            reason=reason,
            ip=client.ip,
            user_agent=(client.user_agent or "")[:512],
        )
    )


def _issue_token(db: Session, user: User, purpose: str, ttl: timedelta) -> str:
    # Invalidate previous unused tokens of the same purpose.
    db.execute(
        update(AuthToken)
        .where(AuthToken.user_id == user.id, AuthToken.purpose == purpose, AuthToken.used_at.is_(None))
        .values(used_at=utcnow())
    )
    raw = new_token()
    db.add(AuthToken(user_id=user.id, purpose=purpose, token_hash=hash_token(raw), expires_at=utcnow() + ttl))
    return raw


def _consume_token(db: Session, raw: str, purpose: str) -> User:
    tok = db.scalar(select(AuthToken).where(AuthToken.token_hash == hash_token(raw), AuthToken.purpose == purpose))
    if tok is None or tok.used_at is not None or tok.expires_at < utcnow():
        raise AuthError("This link is invalid or has expired.", 400)
    tok.used_at = utcnow()
    user = db.get(User, tok.user_id)
    if user is None:
        raise AuthError("This link is invalid or has expired.", 400)
    return user


def _check_password(password: str, user_email: str, full_name: str) -> None:
    problems = password_problems(password, email=user_email, full_name=full_name)
    if problems:
        raise AuthError("Password does not meet policy: " + " ".join(problems), 422)


def slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60] or "org"


# --------------------------------------------------------------------------------------------- bootstrap
def needs_setup(db: Session) -> bool:
    return db.scalar(select(func.count()).select_from(User)) == 0


def register_first_admin(db: Session, *, org_name: str, full_name: str, email_addr: str, password: str,
                         client: ClientInfo) -> User:
    """Creates the organisation and its first Super Admin. Only possible while no users exist."""
    if not needs_setup(db):
        raise AuthError("Registration is closed. Ask a Super Admin to invite you.", 403)
    _check_password(password, email_addr, full_name)
    rbac.sync_rbac(db)
    org = default_org(db) or Organization(name=org_name.strip(), slug=slugify(org_name), settings={})
    db.add(org)
    db.flush()
    user = User(
        organization_id=org.id,
        email=email_addr.strip().lower(),
        full_name=full_name.strip(),
        password_hash=hash_password(password),
        status="active",
        password_changed_at=utcnow(),
    )
    db.add(user)
    db.flush()
    role = rbac.get_role(db, "super_admin")
    if role is None:
        raise RuntimeError("role catalogue not synchronised (super_admin missing)")
    db.add(UserRole(user_id=user.id, role_id=role.id, granted_by=None))
    raw = _issue_token(db, user, "email_verify", timedelta(hours=get_settings().email_token_ttl_hours))
    audit.record(db, org.id, Actor("user", user.id, user.email, client.ip), "org.bootstrap",
                 target_type="organization", target_id=org.id, target_label=org.name)
    audit.record(db, org.id, Actor("user", user.id, user.email, client.ip), "user.register",
                 target_type="user", target_id=user.id, target_label=user.email, metadata={"role": "super_admin"})
    db.commit()
    _send_verification(user, raw)
    return user


def _send_verification(user: User, raw: str) -> None:
    email.send_email(
        user.email,
        "Verify your email address",
        f"Hello {user.full_name},\n\nConfirm your administrator email address:\n{email.link('/verify-email', raw)}\n\n"
        f"This link expires in {get_settings().email_token_ttl_hours} hours.",
    )


def resend_verification(db: Session, user: User) -> None:
    if user.email_verified_at:
        return
    raw = _issue_token(db, user, "email_verify", timedelta(hours=get_settings().email_token_ttl_hours))
    db.commit()
    _send_verification(user, raw)


def verify_email(db: Session, raw: str, client: ClientInfo) -> User:
    user = _consume_token(db, raw, "email_verify")
    user.email_verified_at = user.email_verified_at or utcnow()
    audit.record(db, user.organization_id, Actor("user", user.id, user.email, client.ip), "user.email_verified",
                 target_type="user", target_id=user.id, target_label=user.email)
    db.commit()
    return user


# --------------------------------------------------------------------------------------------- login
@dataclass
class LoginResult:
    user: User
    session_token: str
    csrf_token: str
    mfa_required: bool


def login(db: Session, email_addr: str, password: str, client: ClientInfo) -> LoginResult:
    s = get_settings()
    org = default_org(db)
    generic = AuthError("Invalid email or password.", 401)
    if org is None:
        verify_password(None, password)  # equalise timing
        raise generic
    user = find_user_by_email(db, org.id, email_addr)
    now = utcnow()

    if user is None:
        verify_password(None, password)
        _event(db, org.id, None, "login", False, client, "unknown_user", email_addr)
        db.flush()
        from app.services import alerts
        alerts.on_failed_login(db, org.id, email_addr, None, client.ip)
        db.commit()
        raise generic

    if user.locked_until and user.locked_until > now:
        _event(db, org.id, user, "login", False, client, "locked")
        db.commit()
        raise AuthError("Account temporarily locked after repeated failed sign-ins. Try again later.", 423)

    if not verify_password(user.password_hash, password):
        user.failed_login_count += 1
        reason = "bad_password"
        if user.failed_login_count >= s.max_failed_logins:
            user.locked_until = now + timedelta(minutes=s.lockout_minutes)
            user.failed_login_count = 0
            reason = "bad_password_locked"
            audit.record(db, org.id, Actor.system(client.ip), "user.locked", target_type="user", target_id=user.id,
                         target_label=user.email, result="failure",
                         metadata={"lockout_minutes": s.lockout_minutes})
            notifications.notify_users(
                db, org.id, notifications.users_with_permission(db, org.id, "users:manage"),
                kind="security.lockout", severity="high", title="Administrator account locked",
                body=f"{user.email} was locked after {s.max_failed_logins} failed sign-in attempts from {client.ip}.",
                link="/audit",
            )
        _event(db, org.id, user, "login", False, client, reason)
        audit.record(db, org.id, Actor("user", None, email_addr[:320], client.ip), "auth.login",
                     target_type="user", target_id=user.id, target_label=user.email, result="failure",
                     metadata={"reason": reason})
        db.flush()
        from app.services import alerts
        alerts.on_failed_login(db, org.id, email_addr, user, client.ip)
        db.commit()
        raise generic

    if user.status != "active":
        _event(db, org.id, user, "login", False, client, f"status_{user.status}")
        db.commit()
        raise AuthError("This account is disabled.", 403)
    if user.email_verified_at is None:
        _event(db, org.id, user, "login", False, client, "email_unverified")
        db.commit()
        resend_verification(db, user)
        raise AuthError("Verify your email address before signing in. A new link has been sent.", 403)

    user.failed_login_count = 0
    user.locked_until = None
    if user.password_hash and needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    token, csrf = _create_session(db, user, client, mfa_verified=not user.mfa_enabled, amr=["pwd"])
    if not user.mfa_enabled:
        _complete_login(db, user, client, "password")
    else:
        _event(db, org.id, user, "login_password_ok_mfa_pending", True, client)
    db.commit()
    return LoginResult(user, token, csrf, mfa_required=user.mfa_enabled)


def _complete_login(db: Session, user: User, client: ClientInfo, method: str) -> None:
    user.last_login_at = utcnow()
    from app.services import alerts
    db.flush()
    alerts.on_successful_login(db, user, client.ip, method)
    _event(db, user.organization_id, user, "login", True, client, method)
    audit.record(db, user.organization_id, Actor.from_user(user, client.ip), "auth.login",
                 target_type="user", target_id=user.id, target_label=user.email, metadata={"method": method})


def _create_session(db: Session, user: User, client: ClientInfo, *, mfa_verified: bool,
                    amr: list[str] | None = None) -> tuple[str, str]:
    s = get_settings()
    token, csrf = new_token(), new_token()
    db.add(
        UserSession(
            user_id=user.id,
            token_hash=hash_token(token),
            csrf_hash=hash_token(csrf),
            ip=client.ip,
            user_agent=(client.user_agent or "")[:512],
            mfa_verified=mfa_verified,
            amr={"amr": amr or []},
            expires_at=utcnow() + timedelta(hours=s.session_absolute_timeout_hours),
        )
    )
    return token, csrf


def resolve_session(db: Session, raw_token: str | None) -> UserSession | None:
    if not raw_token:
        return None
    sess = db.scalar(select(UserSession).where(UserSession.token_hash == hash_token(raw_token)))
    if sess is None or sess.revoked_at is not None:
        return None
    now = utcnow()
    idle = timedelta(minutes=get_settings().session_idle_timeout_minutes)
    if sess.expires_at < now or sess.last_seen_at + idle < now:
        sess.revoked_at = now
        sess.revoked_reason = "expired"
        db.commit()
        return None
    if (now - sess.last_seen_at).total_seconds() > 30:
        sess.last_seen_at = now
        db.commit()
    return sess


def verify_mfa_login(db: Session, sess: UserSession, user: User, code: str, client: ClientInfo) -> None:
    if sess.mfa_verified:
        return
    step = totp.verify(crypto.decrypt(user.mfa_secret_enc or "", str(user.id)), code, user.mfa_last_used_step) \
        if user.mfa_secret_enc else None
    if step is None:
        user.failed_login_count += 1
        _event(db, user.organization_id, user, "mfa", False, client, "bad_code")
        if user.failed_login_count >= get_settings().max_failed_logins:
            user.locked_until = utcnow() + timedelta(minutes=get_settings().lockout_minutes)
            user.failed_login_count = 0
            sess.revoked_at = utcnow()
            sess.revoked_reason = "mfa_lockout"
            audit.record(db, user.organization_id, Actor.system(client.ip), "user.locked", target_type="user",
                         target_id=user.id, target_label=user.email, result="failure", metadata={"stage": "mfa"})
        db.commit()
        raise AuthError("Invalid or already-used authentication code.", 401)
    user.mfa_last_used_step = step
    user.failed_login_count = 0
    sess.mfa_verified = True
    sess.amr = {"amr": ["pwd", "otp", "mfa"]}
    _complete_login(db, user, client, "password+totp")
    db.commit()


def logout(db: Session, sess: UserSession, user: User, client: ClientInfo) -> None:
    sess.revoked_at = utcnow()
    sess.revoked_reason = "logout"
    _event(db, user.organization_id, user, "logout", True, client)
    audit.record(db, user.organization_id, Actor.from_user(user, client.ip), "auth.logout",
                 target_type="user", target_id=user.id, target_label=user.email)
    db.commit()


def revoke_user_sessions(db: Session, user_id: uuid.UUID, reason: str, except_id: uuid.UUID | None = None) -> int:
    q = update(UserSession).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
    if except_id:
        q = q.where(UserSession.id != except_id)
    return db.execute(q.values(revoked_at=utcnow(), revoked_reason=reason)).rowcount or 0


# --------------------------------------------------------------------------------------------- MFA enrolment
def begin_mfa_setup(db: Session, user: User) -> tuple[str, str]:
    if user.mfa_enabled:
        raise AuthError("MFA is already enabled.", 409)
    secret = totp.new_secret()
    user.mfa_pending_secret_enc = crypto.encrypt(secret, str(user.id))
    db.commit()
    return secret, totp.provisioning_uri(secret, user.email, get_settings().app_name)


def confirm_mfa_setup(db: Session, user: User, code: str, client: ClientInfo) -> None:
    if not user.mfa_pending_secret_enc:
        raise AuthError("Start MFA setup first.", 409)
    secret = crypto.decrypt(user.mfa_pending_secret_enc, str(user.id))
    step = totp.verify(secret, code, None)
    if step is None:
        raise AuthError("Invalid authentication code.", 400)
    user.mfa_secret_enc = user.mfa_pending_secret_enc
    user.mfa_pending_secret_enc = None
    user.mfa_enabled = True
    user.mfa_last_used_step = step
    _event(db, user.organization_id, user, "mfa_enabled", True, client)
    audit.record(db, user.organization_id, Actor.from_user(user, client.ip), "auth.mfa_enabled",
                 target_type="user", target_id=user.id, target_label=user.email)
    db.commit()


def disable_mfa(db: Session, user: User, password: str, code: str, client: ClientInfo) -> None:
    if not user.mfa_enabled or not user.mfa_secret_enc:
        raise AuthError("MFA is not enabled.", 409)
    if not verify_password(user.password_hash, password):
        raise AuthError("Current password is incorrect.", 401)
    step = totp.verify(crypto.decrypt(user.mfa_secret_enc, str(user.id)), code, user.mfa_last_used_step)
    if step is None:
        raise AuthError("Invalid authentication code.", 400)
    user.mfa_enabled = False
    user.mfa_secret_enc = None
    user.mfa_last_used_step = None
    _event(db, user.organization_id, user, "mfa_disabled", True, client)
    audit.record(db, user.organization_id, Actor.from_user(user, client.ip), "auth.mfa_disabled",
                 target_type="user", target_id=user.id, target_label=user.email)
    db.commit()


# --------------------------------------------------------------------------------------------- passwords
def request_password_reset(db: Session, email_addr: str, client: ClientInfo) -> None:
    """Always behaves identically whether or not the account exists (no user enumeration)."""
    org = default_org(db)
    user = find_user_by_email(db, org.id, email_addr) if org else None
    if user is None or user.status != "active":
        if org:
            _event(db, org.id, None, "password_reset_request", False, client, "unknown_user", email_addr)
            db.commit()
        return
    raw = _issue_token(db, user, "password_reset", timedelta(minutes=get_settings().reset_token_ttl_minutes))
    _event(db, org.id, user, "password_reset_request", True, client)
    db.commit()
    email.send_email(
        user.email,
        "Password reset",
        f"A password reset was requested for your account from {client.ip}.\n\n"
        f"Reset link (valid {get_settings().reset_token_ttl_minutes} minutes):\n{email.link('/reset-password', raw)}\n\n"
        "If you did not request this, ignore this email and notify your security team.",
    )


def reset_password(db: Session, raw: str, new_password: str, client: ClientInfo) -> None:
    user = _consume_token(db, raw, "password_reset")
    _check_password(new_password, user.email, user.full_name)
    user.password_hash = hash_password(new_password)
    user.password_changed_at = utcnow()
    user.failed_login_count = 0
    user.locked_until = None
    revoked = revoke_user_sessions(db, user.id, "password_reset")
    _event(db, user.organization_id, user, "password_reset", True, client)
    audit.record(db, user.organization_id, Actor("user", user.id, user.email, client.ip), "auth.password_reset",
                 target_type="user", target_id=user.id, target_label=user.email, metadata={"sessions_revoked": revoked})
    db.commit()


def change_password(db: Session, user: User, sess: UserSession, current: str, new: str, client: ClientInfo) -> None:
    if not verify_password(user.password_hash, current):
        _event(db, user.organization_id, user, "password_change", False, client, "bad_current_password")
        db.commit()
        raise AuthError("Current password is incorrect.", 401)
    if current == new:
        raise AuthError("New password must differ from the current password.", 422)
    _check_password(new, user.email, user.full_name)
    user.password_hash = hash_password(new)
    user.password_changed_at = utcnow()
    revoked = revoke_user_sessions(db, user.id, "password_changed", except_id=sess.id)
    _event(db, user.organization_id, user, "password_change", True, client)
    audit.record(db, user.organization_id, Actor.from_user(user, client.ip), "auth.password_changed",
                 target_type="user", target_id=user.id, target_label=user.email,
                 metadata={"other_sessions_revoked": revoked})
    db.commit()


def accept_invite(db: Session, raw: str, password: str, client: ClientInfo) -> User:
    user = _consume_token(db, raw, "invite")
    if user.status != "pending":
        raise AuthError("This invitation has already been used.", 400)
    _check_password(password, user.email, user.full_name)
    user.password_hash = hash_password(password)
    user.password_changed_at = utcnow()
    user.status = "active"
    user.email_verified_at = utcnow()  # possession of the emailed invite link proves the address
    _event(db, user.organization_id, user, "invite_accepted", True, client)
    audit.record(db, user.organization_id, Actor("user", user.id, user.email, client.ip), "user.invite_accepted",
                 target_type="user", target_id=user.id, target_label=user.email)
    db.commit()
    return user


def issue_invite(db: Session, user: User) -> str:
    return _issue_token(db, user, "invite", timedelta(hours=get_settings().invite_token_ttl_hours))
