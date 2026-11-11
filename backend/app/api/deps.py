"""Request dependencies: authentication, CSRF and permission enforcement."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.middleware import client_ip
from app.core.rate_limit import get_rate_limiter
from app.models import User, UserSession
from app.security.tokens import constant_time_equals, hash_token
from app.services import audit, auth
from app.services.audit import Actor

SESSION_COOKIE = "cage_session"
CSRF_COOKIE = "cage_csrf"
CSRF_HEADER = "x-csrf-token"


@dataclass
class AuthContext:
    user: User
    session: UserSession
    client: auth.ClientInfo

    @property
    def permissions(self) -> set[str]:
        return self.user.permission_keys

    @property
    def actor(self) -> Actor:
        return Actor.from_user(self.user, self.client.ip)


def client_info(request: Request) -> auth.ClientInfo:
    return auth.ClientInfo(ip=client_ip(request), user_agent=request.headers.get("user-agent"))


def _check_csrf(request: Request, sess: UserSession) -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    header = request.headers.get(CSRF_HEADER)
    if not header or not constant_time_equals(hash_token(header), sess.csrf_hash):
        raise HTTPException(status_code=403, detail="CSRF token missing or invalid")


def _session(request: Request, db: Session) -> tuple[UserSession, User]:
    sess = auth.resolve_session(db, request.cookies.get(SESSION_COOKIE))
    if sess is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = db.get(User, sess.user_id)
    if user is None or user.status != "active":
        raise HTTPException(status_code=401, detail="Not authenticated")
    _check_csrf(request, sess)
    return sess, user


def current_context(request: Request, db: Session = Depends(get_db)) -> AuthContext:
    sess, user = _session(request, db)
    if not sess.mfa_verified:
        raise HTTPException(status_code=401, detail="MFA verification required")
    return AuthContext(user, sess, client_info(request))


def require_permission(*perms: str, any_of: bool = False) -> Callable[..., AuthContext]:
    """Backend-enforced authorization. Denials are audited."""

    def dep(ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)) -> AuthContext:
        have = ctx.permissions
        ok = any(p in have for p in perms) if any_of else all(p in have for p in perms)
        if not ok:
            audit.record(db, ctx.user.organization_id, ctx.actor, "authz.denied", result="denied",
                         metadata={"required": list(perms)})
            db.commit()
            raise HTTPException(status_code=403, detail="You do not have permission to perform this action")
        return ctx

    return dep


def rate_limit(scope: str, limit: int, window_seconds: int = 60) -> Callable[[Request], None]:
    def dep(request: Request) -> None:
        key = f"{scope}:{client_ip(request)}"
        if not get_rate_limiter().hit(key, limit, window_seconds):
            raise HTTPException(status_code=429, detail="Too many requests. Slow down and try again shortly.")

    return dep
