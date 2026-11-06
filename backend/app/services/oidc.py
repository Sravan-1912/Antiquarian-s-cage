"""OpenID Connect provider (authorization code flow + PKCE S256), for applications registered in the console.

Security properties:
* Redirect URIs are matched exactly against the registered list; unknown client/redirect never redirects.
* PKCE (S256) is mandatory for every client; public clients must use it instead of a secret.
* Codes are 256-bit, stored hashed, single-use, valid 60 s, bound to client + redirect_uri + PKCE verifier.
* The user must hold an active assignment to the application (checked at authorize, token and userinfo time).
* Applications may require MFA: the session's RFC 8176 `amr` must contain "mfa" (OTP or passkey sign-in).
* ID tokens are RS256-signed (kid published at the JWKS endpoint), 5-minute lifetime; access tokens 10 minutes.
* An application is marked *verified* only after a real code exchange has succeeded.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta

import jwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utcnow
from app.models import (
    Application, ApplicationAssignment, AuthenticationEvent, Employee, OIDCAuthorizationCode, User,
)
from app.security.oidc_keys import get_oidc_key
from app.security.tokens import hash_token
from app.services import audit
from app.services.audit import Actor

SCOPES = {"openid", "profile", "email"}
CODE_TTL = timedelta(seconds=60)
ID_TOKEN_TTL = timedelta(minutes=5)
ACCESS_TOKEN_TTL = timedelta(minutes=10)


class OIDCError(Exception):
    def __init__(self, error: str, description: str, status: int = 400, redirectable: bool = True):
        super().__init__(description)
        self.error, self.description, self.status, self.redirectable = error, description, status, redirectable


def issuer() -> str:
    return get_settings().public_base_url.rstrip("/") + "/api/v1/oidc"


def discovery() -> dict:
    iss = issuer()
    return {
        "issuer": iss,
        "authorization_endpoint": f"{iss}/authorize",
        "token_endpoint": f"{iss}/token",
        "userinfo_endpoint": f"{iss}/userinfo",
        "jwks_uri": f"{iss}/jwks",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": sorted(SCOPES),
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "amr", "email", "email_verified",
                             "name", "employee_number", "department"],
    }


def _event(db: Session, app: Application, user: User | None, kind: str, ok: bool, reason: str | None,
           ip: str | None, ua: str | None) -> None:
    db.add(AuthenticationEvent(organization_id=app.organization_id, user_id=user.id if user else None,
                               email_attempted=user.email if user else None, event_type=kind, success=ok,
                               reason=reason, application_id=app.id, ip=ip, user_agent=(ua or "")[:512]))


def employee_for(db: Session, user: User) -> Employee | None:
    return db.scalar(select(Employee).where(Employee.user_id == user.id, Employee.organization_id == user.organization_id))


def assignment_active(db: Session, app: Application, user: User) -> bool:
    emp = employee_for(db, user)
    if emp is None or emp.status != "active":
        return False
    return db.scalar(select(ApplicationAssignment.id).where(
        ApplicationAssignment.application_id == app.id, ApplicationAssignment.employee_id == emp.id,
        ApplicationAssignment.revoked_at.is_(None))) is not None


def client_by_id(db: Session, client_id: str) -> Application | None:
    return db.scalar(select(Application).where(Application.client_id == client_id))


def validate_authorize_request(db: Session, params: dict) -> tuple[Application, str]:
    """Errors raised with redirectable=False must be shown to the user, never sent to the (unverified) redirect."""
    app = client_by_id(db, params.get("client_id") or "")
    if app is None or app.status != "active":
        raise OIDCError("invalid_client", "Unknown or disabled application", redirectable=False)
    redirect_uri = params.get("redirect_uri") or ""
    if redirect_uri not in (app.redirect_uris or {}).get("uris", []):
        raise OIDCError("invalid_request", "redirect_uri is not registered for this application", redirectable=False)
    if params.get("response_type") != "code":
        raise OIDCError("unsupported_response_type", "Only the authorization code flow is supported")
    scopes = set((params.get("scope") or "").split())
    if "openid" not in scopes or not scopes <= SCOPES:
        raise OIDCError("invalid_scope", f"Scope must include openid and only {sorted(SCOPES)}")
    if params.get("code_challenge_method") != "S256" or not (43 <= len(params.get("code_challenge") or "") <= 128):
        raise OIDCError("invalid_request", "PKCE with code_challenge_method=S256 is required")
    return app, redirect_uri


def issue_code(db: Session, app: Application, user: User, params: dict, amr: list[str], auth_time: datetime,
               ip: str | None, ua: str | None) -> str:
    raw = secrets.token_urlsafe(32)
    db.add(OIDCAuthorizationCode(code_hash=hash_token(raw), application_id=app.id, user_id=user.id,
                                 redirect_uri=params["redirect_uri"], scope=params["scope"],
                                 nonce=(params.get("nonce") or None), code_challenge=params["code_challenge"],
                                 amr={"amr": amr}, auth_time=auth_time, expires_at=utcnow() + CODE_TTL))
    _event(db, app, user, "sso_authorize", True, None, ip, ua)
    db.commit()
    return raw


def _verify_client(app: Application, secret: str | None) -> None:
    if app.client_type == "confidential":
        if not secret or not app.client_secret_hash or not hmac.compare_digest(hash_token(secret),
                                                                               app.client_secret_hash):
            raise OIDCError("invalid_client", "Client authentication failed", 401)
    elif secret:
        raise OIDCError("invalid_client", "Public clients must not send a secret", 401)


def exchange_code(db: Session, *, client_id: str, client_secret: str | None, code: str, redirect_uri: str,
                  code_verifier: str, ip: str | None, ua: str | None) -> dict:
    app = client_by_id(db, client_id)
    if app is None or app.status != "active":
        raise OIDCError("invalid_client", "Unknown or disabled application", 401)
    _verify_client(app, client_secret)
    rec = db.scalar(select(OIDCAuthorizationCode).where(OIDCAuthorizationCode.code_hash == hash_token(code)))
    if rec is None or rec.application_id != app.id:
        raise OIDCError("invalid_grant", "Invalid authorization code")
    if rec.used_at is not None:
        raise OIDCError("invalid_grant", "Authorization code already used")
    rec.used_at = utcnow()
    db.commit()  # burn the code before any further check (single use even on failure)
    if rec.expires_at < utcnow() or rec.redirect_uri != redirect_uri:
        raise OIDCError("invalid_grant", "Authorization code expired or redirect_uri mismatch")
    expected = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
    if not (43 <= len(code_verifier) <= 128) or not hmac.compare_digest(expected, rec.code_challenge):
        raise OIDCError("invalid_grant", "PKCE verification failed")
    user = db.get(User, rec.user_id)
    if user is None or user.status != "active" or not assignment_active(db, app, user):
        _event(db, app, user, "sso_token", False, "access_revoked", ip, ua)
        db.commit()
        raise OIDCError("invalid_grant", "User no longer has access to this application")

    key = get_oidc_key()
    now = utcnow()
    emp = employee_for(db, user)
    scopes = set(rec.scope.split())
    amr = (rec.amr or {}).get("amr", [])
    claims: dict = {"iss": issuer(), "sub": str(user.id), "aud": app.client_id, "iat": int(now.timestamp()),
                    "exp": int((now + ID_TOKEN_TTL).timestamp()), "auth_time": int(rec.auth_time.timestamp()),
                    "amr": amr, "azp": app.client_id}
    if rec.nonce:
        claims["nonce"] = rec.nonce
    if "email" in scopes:
        claims |= {"email": user.email, "email_verified": user.email_verified_at is not None}
    if "profile" in scopes:
        claims |= {"name": user.full_name}
        if emp:
            claims |= {"employee_number": emp.employee_number, "department": emp.department}
    id_token = jwt.encode(claims, key.private_key, algorithm="RS256", headers={"kid": key.kid})
    access_token = jwt.encode({"iss": issuer(), "sub": str(user.id), "aud": issuer() + "/userinfo",
                               "client_id": app.client_id, "scope": rec.scope, "iat": int(now.timestamp()),
                               "exp": int((now + ACCESS_TOKEN_TTL).timestamp()), "jti": uuid.uuid4().hex},
                              key.private_key, algorithm="RS256", headers={"kid": key.kid, "typ": "at+jwt"})
    first = app.verified_at is None
    if first:
        app.verified_at = now  # a real end-to-end code exchange just succeeded
    _event(db, app, user, "sso_token", True, None, ip, ua)
    audit.record(db, app.organization_id, Actor("user", user.id, user.email, ip), "sso.token_issued",
                 target_type="application", target_id=app.id, target_label=app.name,
                 metadata={"amr": amr, "first_verified_flow": first})
    db.commit()
    return {"access_token": access_token, "token_type": "Bearer", "expires_in": int(ACCESS_TOKEN_TTL.total_seconds()),
            "id_token": id_token, "scope": rec.scope}


def userinfo(db: Session, token: str) -> dict:
    key = get_oidc_key()
    try:
        claims = jwt.decode(token, key.private_key.public_key(), algorithms=["RS256"], audience=issuer() + "/userinfo",
                            issuer=issuer())
    except jwt.PyJWTError as exc:
        raise OIDCError("invalid_token", str(exc), 401) from exc
    user = db.get(User, uuid.UUID(claims["sub"]))
    app = client_by_id(db, claims.get("client_id", ""))
    if user is None or app is None or user.status != "active" or app.status != "active" \
            or not assignment_active(db, app, user):
        raise OIDCError("invalid_token", "Access has been revoked", 401)
    scopes = set(claims.get("scope", "").split())
    out = {"sub": str(user.id)}
    if "email" in scopes:
        out |= {"email": user.email, "email_verified": user.email_verified_at is not None}
    if "profile" in scopes:
        out["name"] = user.full_name
        emp = employee_for(db, user)
        if emp:
            out |= {"employee_number": emp.employee_number, "department": emp.department}
    return out
