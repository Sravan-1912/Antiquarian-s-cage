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
from app.models import AuthenticationEvent, AuthToken, Organization, User, UserRole, UserSession
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


def slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60] or "org"


# --------------------------------------------------------------------------------------------- bootstrap
def needs_setup(db: Session) -> bool:
    return db.scalar(select(func.count()).select_from(User)) == 0


def register_first_admin(db: Session, *, org_name: str, full_name: str, email_addr: str,
                         client: ClientInfo) -> tuple[User, str]:
    """Create the organisation and its first Super Admin (passwordless). Only possible while no users exist. Returns
    (user, enroll_token): the account is `pending` until the browser registers a passkey with that single-use token."""
    if not needs_setup(db):
        raise AuthError("Registration is closed. Ask a Super Admin to invite you.", 403)
    rbac.sync_rbac(db)
    org = default_org(db) or Organization(name=org_name.strip(), slug=slugify(org_name), settings={})
    db.add(org)
    db.flush()
    user = User(organization_id=org.id, email=email_addr.strip().lower(), full_name=full_name.strip(),
                status="pending")
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
    enroll = _issue_token(db, user, "passkey_enroll", timedelta(hours=get_settings().invite_token_ttl_hours))
    db.commit()
    return user, enroll


# --------------------------------------------------------------------------------------------- login
@dataclass
class LoginResult:
    user: User
    session_token: str
    csrf_token: str
    mfa_required: bool


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


# --------------------------------------------------------------------------------------------- MFA enrolment
# --------------------------------------------------------------------------------------------- passwords
def issue_invite(db: Session, user: User) -> str:
    return _issue_token(db, user, "invite", timedelta(hours=get_settings().invite_token_ttl_hours))


# ------------------------------------------------------------------------- passkey enrolment (passwordless)
# An invite link doubles as a first-passkey enrolment link, so an invited admin can register a passkey instead of
# setting a password. Recovery tokens re-enrol a passkey for a locked-out account (admin-issued or break-glass).
ENROLL_PURPOSES = ("passkey_enroll", "passkey_recovery", "invite")


def peek_enroll_user(db: Session, raw: str) -> tuple[User, str]:
    """Resolve (user, purpose) for an unused, unexpired enrolment/invite/recovery token WITHOUT consuming it, so the
    registration options and the verify step can use the same token."""
    tok = db.scalar(select(AuthToken).where(AuthToken.token_hash == hash_token(raw),
                                            AuthToken.purpose.in_(ENROLL_PURPOSES)))
    if tok is None or tok.used_at is not None or tok.expires_at < utcnow():
        raise AuthError("This link is invalid or has expired.", 400)
    user = db.get(User, tok.user_id)
    if user is None or user.status == "disabled":
        raise AuthError("This link is invalid or has expired.", 400)
    return user, tok.purpose


def issue_recovery(db: Session, user: User) -> str:
    """Single-use token that lets a user register a fresh passkey (replaces password reset). Admin-issued only."""
    return _issue_token(db, user, "passkey_recovery", timedelta(hours=1))


def complete_enroll(db: Session, raw: str, user: User, purpose: str, client: ClientInfo) -> LoginResult:
    """Consume the enrolment token, activate the account, revoke old passkeys on recovery, and start a session. The
    passkey itself is registered by passkeys.register() just before this is called (it owns the WebAuthn verify)."""
    tok = db.scalar(select(AuthToken).where(AuthToken.token_hash == hash_token(raw),
                                            AuthToken.purpose.in_(ENROLL_PURPOSES)))
    if tok is None or tok.used_at is not None or tok.expires_at < utcnow() or tok.user_id != user.id:
        raise AuthError("This link is invalid or has expired.", 400)
    tok.used_at = utcnow()
    user.status = "active"
    user.email_verified_at = user.email_verified_at or utcnow()  # possession of the emailed link proves the address
    user.failed_login_count = 0
    user.locked_until = None
    event = "invite_accepted" if purpose == "invite" else ("passkey_recovered" if purpose == "passkey_recovery"
                                                            else "passkey_enrolled")
    _event(db, user.organization_id, user, event, True, client)
    audit.record(db, user.organization_id, Actor("user", user.id, user.email, client.ip), f"user.{event}",
                 target_type="user", target_id=user.id, target_label=user.email, metadata={"via": purpose})
    token, csrf = _create_session(db, user, client, mfa_verified=True, amr=["hwk", "user", "mfa", "passkey"])
    _complete_login(db, user, client, "passkey")
    db.commit()
    return LoginResult(user, token, csrf, mfa_required=False)
