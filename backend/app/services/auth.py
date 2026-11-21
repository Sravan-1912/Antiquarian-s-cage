"""Authentication (passkey-only): passwordless bootstrap, sessions, passkey enrolment and recovery tokens."""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utcnow
from app.models import AuthenticationEvent, Organization, User, UserRole, UserSession
from app.security.passwords import PasswordPolicyError  # re-exported for the API layer
from app.security.tokens import hash_token, new_token
from app.services import audit, rbac
from app.services.audit import Actor


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


def slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60] or "org"


# --------------------------------------------------------------------------------------------- bootstrap
def needs_setup(db: Session) -> bool:
    return db.scalar(select(func.count()).select_from(User)) == 0


def register_first_admin(db: Session, *, org_name: str, full_name: str, email_addr: str, password: str,
                         client: ClientInfo) -> LoginResult:
    """Create the organisation and its first Super Admin with a password, and sign them in. Only possible while no
    users exist (first-run setup)."""
    from app.security import passwords
    if not needs_setup(db):
        raise AuthError("Registration is closed. Ask a Super Admin to create your account.", 403)
    passwords.validate_strength(password)
    rbac.sync_rbac(db)
    org = default_org(db) or Organization(name=org_name.strip(), slug=slugify(org_name), settings={})
    db.add(org)
    db.flush()
    user = User(organization_id=org.id, email=email_addr.strip().lower(), full_name=full_name.strip(),
                status="active", password_hash=passwords.hash_password(password),
                email_verified_at=utcnow())
    db.add(user)
    db.flush()
    role = rbac.get_role(db, "super_admin")
    if role is None:
        raise RuntimeError("role catalogue not synchronised (super_admin missing)")
    db.add(UserRole(user_id=user.id, role_id=role.id, granted_by=None))
    audit.record(db, org.id, Actor("user", user.id, user.email, client.ip), "org.bootstrap",
                 target_type="organization", target_id=org.id, target_label=org.name)
    audit.record(db, org.id, Actor("user", user.id, user.email, client.ip), "user.register",
                 target_type="user", target_id=user.id, target_label=user.email, metadata={"role": "super_admin"})
    token, csrf = _create_session(db, user, client, mfa_verified=True, amr=["pwd"])
    _complete_login(db, user, client, "password")
    db.commit()
    return LoginResult(user, token, csrf, mfa_required=False)


# --------------------------------------------------------------------------------------------- passwords
def set_password(db: Session, user: User, raw: str) -> None:
    """Validate and store a new password; clears the forced-change flag and the lockout counters."""
    from app.security import passwords
    passwords.validate_strength(raw)
    user.password_hash = passwords.hash_password(raw)
    user.must_change_password = False
    user.failed_login_count = 0
    user.locked_until = None


def _find_login_user(db: Session, email_addr: str) -> User | None:
    """Find the account to sign in by email. Emails are unique per organisation; prefer an account that has a
    password set (one that can actually sign in)."""
    rows = db.scalars(
        select(User).where(func.lower(User.email) == email_addr.strip().lower()).order_by(User.created_at)
    ).all()
    return next((u for u in rows if u.password_hash), None) or (rows[0] if rows else None)


def login_with_password(db: Session, email_addr: str, password: str, client: ClientInfo) -> LoginResult:
    """Password sign-in with lockout. Failures are deliberately indistinguishable (no user enumeration)."""
    from app.security import passwords
    s = get_settings()
    user = _find_login_user(db, email_addr)
    now = utcnow()
    bad = AuthError("Incorrect email or password.", 401)
    if user is None or user.password_hash is None:
        _event(db, None, None, "login", False, client, "no_such_user", email_addr)
        db.commit()
        raise bad
    if user.status == "disabled":
        _event(db, user.organization_id, user, "login", False, client, "disabled")
        db.commit()
        raise AuthError("This account has been disabled.", 403)
    if user.locked_until and user.locked_until > now:
        _event(db, user.organization_id, user, "login", False, client, "locked")
        db.commit()
        raise AuthError("Too many attempts. This account is temporarily locked; try again later.", 423)
    if not passwords.verify_password(password, user.password_hash):
        user.failed_login_count += 1
        if user.failed_login_count >= s.max_failed_logins:
            user.locked_until = now + timedelta(minutes=s.lockout_minutes)
            user.failed_login_count = 0
        _event(db, user.organization_id, user, "login", False, client, "bad_password")
        db.flush()  # the burst-detection count below must see this event
        from app.services import alerts
        alerts.on_failed_login(db, user.organization_id, user.email, user, client.ip)
        db.commit()
        raise bad
    user.failed_login_count = 0
    user.locked_until = None
    token, csrf = _create_session(db, user, client, mfa_verified=True, amr=["pwd"])
    _complete_login(db, user, client, "password")
    db.commit()
    return LoginResult(user, token, csrf, mfa_required=False, must_change_password=user.must_change_password)


def change_password(db: Session, user: User, current: str, new: str, client: ClientInfo,
                    *, keep_session_id: uuid.UUID | None = None) -> None:
    """Change the signed-in user's own password: verify the current one, set the new one, and sign out other
    sessions. Used both for a voluntary change and the forced change after a handover."""
    from app.security import passwords
    if not passwords.verify_password(current, user.password_hash):
        raise AuthError("Your current password is incorrect.", 400)
    if passwords.verify_password(new, user.password_hash):
        raise AuthError("Choose a password different from your current one.", 400)
    set_password(db, user, new)
    revoke_user_sessions(db, user.id, "password_changed", except_id=keep_session_id)
    _event(db, user.organization_id, user, "password_changed", True, client)
    audit.record(db, user.organization_id, Actor.from_user(user, client.ip), "auth.password_changed",
                 target_type="user", target_id=user.id, target_label=user.email)
    db.commit()


def set_temporary_password(db: Session, user: User) -> str:
    """Generate a one-time password for this account and require a change on next sign-in. Returns the clear-text
    password ONCE so a Super Admin can hand it over; it is never stored or shown again."""
    from app.security import passwords
    temp = passwords.generate_temporary()
    user.password_hash = passwords.hash_password(temp)
    user.must_change_password = True
    user.failed_login_count = 0
    user.locked_until = None
    return temp


# --------------------------------------------------------------------------------------------- login
@dataclass
class LoginResult:
    user: User
    session_token: str
    csrf_token: str
    mfa_required: bool
    must_change_password: bool = False


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


