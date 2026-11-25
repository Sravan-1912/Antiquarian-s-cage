"""WebAuthn passkeys (registration, sign-in, management) built on py_webauthn — no homemade crypto or protocol.

* Biometrics are verified by the user's own authenticator (Windows Hello, Touch ID, security key…); the server only
  ever receives a public key and signed assertions.
* User verification is REQUIRED, so a passkey sign-in is phishing-resistant multi-factor (possession + PIN/biometric).
* Challenges are single-use, stored server-side, and expire after 5 minutes.
* Sign counters are checked to detect cloned authenticators (when the authenticator implements counters).
"""
from __future__ import annotations

import json
import secrets
import uuid
from datetime import timedelta
from urllib.parse import urlparse

from sqlalchemy import delete, select
from sqlalchemy.orm import Session
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.core.config import get_settings
from app.core.database import utcnow
from app.models import User, WebAuthnChallenge, WebAuthnCredential
from app.services import audit
from app.services.audit import Actor
from app.services.auth import AuthError, ClientInfo, _complete_login, _create_session, _event

CHALLENGE_TTL = timedelta(minutes=5)


def rp() -> tuple[str, str, str]:
    """(rp_id, rp_name, expected_origin) derived from PUBLIC_BASE_URL."""
    s = get_settings()
    origin = s.public_base_url.rstrip("/")
    return urlparse(origin).hostname or "localhost", s.app_name, origin


def _new_challenge(db: Session, purpose: str, user_id: uuid.UUID | None, challenge: bytes) -> WebAuthnChallenge:
    db.execute(delete(WebAuthnChallenge).where(WebAuthnChallenge.expires_at < utcnow()))
    c = WebAuthnChallenge(id=uuid.uuid4(), purpose=purpose, user_id=user_id, challenge=challenge,
                          expires_at=utcnow() + CHALLENGE_TTL)
    db.add(c)
    return c


def _consume(db: Session, challenge_id: uuid.UUID, purpose: str, user_id: uuid.UUID | None) -> bytes:
    c = db.get(WebAuthnChallenge, challenge_id)
    if (c is None or c.purpose != purpose or c.used_at is not None or c.expires_at < utcnow()
            or (user_id is not None and c.user_id != user_id)):
        raise AuthError("Passkey challenge is invalid or expired. Try again.", 400)
    c.used_at = utcnow()
    return c.challenge


def active_credentials(db: Session, user_id: uuid.UUID) -> list[WebAuthnCredential]:
    return list(db.scalars(select(WebAuthnCredential).where(WebAuthnCredential.user_id == user_id,
                                                            WebAuthnCredential.revoked_at.is_(None))
                           .order_by(WebAuthnCredential.created_at)))


# ------------------------------------------------------------------------------------------- registration
def registration_options(db: Session, user: User) -> tuple[uuid.UUID, dict]:
    rp_id, rp_name, _ = rp()
    opts = generate_registration_options(
        rp_id=rp_id, rp_name=rp_name, user_name=user.email, user_display_name=user.full_name,
        user_id=user.id.bytes, challenge=secrets.token_bytes(32), timeout=300_000,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED, user_verification=UserVerificationRequirement.REQUIRED),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=c.credential_id)
                             for c in active_credentials(db, user.id)],
    )
    ch = _new_challenge(db, "register", user.id, opts.challenge)
    db.commit()
    return ch.id, json.loads(options_to_json(opts))


def register(db: Session, user: User, challenge_id: uuid.UUID, credential: dict, name: str,
             client: ClientInfo) -> WebAuthnCredential:
    rp_id, _, origin = rp()
    expected = _consume(db, challenge_id, "register", user.id)
    try:
        v = verify_registration_response(credential=credential, expected_challenge=expected, expected_rp_id=rp_id,
                                         expected_origin=origin, require_user_verification=True)
    except InvalidRegistrationResponse as exc:
        db.commit()  # challenge stays consumed
        _event(db, user.organization_id, user, "passkey_register", False, client, "invalid_response")
        db.commit()
        raise AuthError(f"Passkey registration failed: {exc}", 400) from exc
    if db.scalar(select(WebAuthnCredential.id).where(WebAuthnCredential.credential_id == v.credential_id)):
        raise AuthError("This passkey is already registered", 409)
    cred = WebAuthnCredential(
        user_id=user.id, credential_id=v.credential_id, public_key=v.credential_public_key, sign_count=v.sign_count,
        aaguid=str(v.aaguid) if v.aaguid else None, backed_up=bool(v.credential_backed_up), name=name[:64],
        transports={"transports": (credential.get("response") or {}).get("transports") or []},
    )
    db.add(cred)
    db.flush()
    _event(db, user.organization_id, user, "passkey_register", True, client)
    audit.record(db, user.organization_id, Actor.from_user(user, client.ip), "auth.passkey_registered",
                 target_type="user", target_id=user.id, target_label=user.email,
                 metadata={"credential": str(cred.id), "name": cred.name, "synced": cred.backed_up})
    db.commit()
    return cred


# ------------------------------------------------------------------------------------------- sign-in
def authentication_options(db: Session) -> tuple[uuid.UUID, dict]:
    """Usernameless (discoverable credential) sign-in: no account hints are revealed."""
    rp_id, _, _ = rp()
    opts = generate_authentication_options(rp_id=rp_id, challenge=secrets.token_bytes(32), timeout=300_000,
                                           user_verification=UserVerificationRequirement.REQUIRED)
    ch = _new_challenge(db, "authenticate", None, opts.challenge)
    db.commit()
    return ch.id, json.loads(options_to_json(opts))


def authenticate(db: Session, challenge_id: uuid.UUID, credential: dict, client: ClientInfo):
    from app.services.auth import LoginResult

    rp_id, _, origin = rp()
    expected = _consume(db, challenge_id, "authenticate", None)
    generic = AuthError("Passkey sign-in failed.", 401)
    raw_id = credential.get("rawId") or credential.get("id") or ""
    from webauthn.helpers import base64url_to_bytes
    try:
        cred_id = base64url_to_bytes(raw_id)
    except ValueError:
        db.commit()
        raise generic
    cred = db.scalar(select(WebAuthnCredential).where(WebAuthnCredential.credential_id == cred_id))
    if cred is None or cred.revoked_at is not None:
        db.commit()
        raise generic
    user = db.get(User, cred.user_id)
    try:
        v = verify_authentication_response(credential=credential, expected_challenge=expected, expected_rp_id=rp_id,
                                           expected_origin=origin, credential_public_key=cred.public_key,
                                           credential_current_sign_count=cred.sign_count,
                                           require_user_verification=True)
    except InvalidAuthenticationResponse as exc:
        _event(db, user.organization_id, user, "login", False, client, f"passkey_invalid: {str(exc)[:80]}")
        audit.record(db, user.organization_id, Actor("user", None, user.email, client.ip), "auth.login",
                     target_type="user", target_id=user.id, target_label=user.email, result="failure",
                     metadata={"method": "passkey", "reason": str(exc)[:200]})
        db.flush()
        from app.services import alerts
        alerts.on_failed_login(db, user.organization_id, user.email, user, client.ip)  # feeds failed-sign-in rules
        db.commit()
        raise generic from exc
    if user.status != "active":
        _event(db, user.organization_id, user, "login", False, client, f"status_{user.status}")
        db.commit()
        raise AuthError("This account is disabled.", 403)
    if user.locked_until and user.locked_until > utcnow():
        raise AuthError("Account temporarily locked after repeated failed sign-ins. Try again later.", 423)
    cred.sign_count = v.new_sign_count
    cred.last_used_at = utcnow()
    user.failed_login_count = 0
    amr = ["swk" if cred.backed_up else "hwk", "user", "mfa"]
    token, csrf = _create_session(db, user, client, mfa_verified=True, amr=amr)
    _complete_login(db, user, client, "passkey")
    db.commit()
    return LoginResult(user, token, csrf, mfa_required=False)


def revoke(db: Session, cred: WebAuthnCredential, actor: Actor, by_user_id: uuid.UUID | None) -> None:
    cred.revoked_at = utcnow()
    cred.revoked_by = by_user_id
    user = db.get(User, cred.user_id)
    audit.record(db, user.organization_id, actor, "auth.passkey_revoked", target_type="user", target_id=user.id,
                 target_label=user.email, metadata={"credential": str(cred.id), "name": cred.name})
    db.commit()


def verify_step_up(db: Session, user: User, challenge_id: uuid.UUID, credential: dict, client: ClientInfo) -> bool:
    """Fresh-passkey confirmation for a sensitive action (replaces re-entering a password). Verifies an assertion from
    one of THIS user's passkeys against a challenge issued to them; no session is created. Returns True on success."""
    rp_id, _, origin = rp()
    try:
        expected = _consume(db, challenge_id, "step_up", user.id)
    except AuthError:
        return False
    from webauthn.helpers import base64url_to_bytes
    try:
        cred_id = base64url_to_bytes(credential.get("rawId") or credential.get("id") or "")
    except ValueError:
        db.commit()
        return False
    cred = db.scalar(select(WebAuthnCredential).where(WebAuthnCredential.credential_id == cred_id,
                                                      WebAuthnCredential.user_id == user.id,
                                                      WebAuthnCredential.revoked_at.is_(None)))
    if cred is None:
        db.commit()
        return False
    try:
        v = verify_authentication_response(credential=credential, expected_challenge=expected, expected_rp_id=rp_id,
                                           expected_origin=origin, credential_public_key=cred.public_key,
                                           credential_current_sign_count=cred.sign_count,
                                           require_user_verification=True)
    except InvalidAuthenticationResponse:
        db.commit()
        return False
    cred.sign_count = v.new_sign_count
    cred.last_used_at = utcnow()
    db.flush()
    return True


def step_up_options(db: Session, user: User) -> tuple[uuid.UUID, dict]:
    """Assertion options for a step-up challenge bound to the signed-in user."""
    rp_id, _, _ = rp()
    opts = generate_authentication_options(rp_id=rp_id, challenge=secrets.token_bytes(32), timeout=120_000,
                                           user_verification=UserVerificationRequirement.REQUIRED,
                                           allow_credentials=[PublicKeyCredentialDescriptor(id=c.credential_id)
                                                              for c in active_credentials(db, user.id)])
    ch = _new_challenge(db, "step_up", user.id, opts.challenge)
    db.commit()
    return ch.id, json.loads(options_to_json(opts))


def revoke_all(db: Session, user: User, actor: Actor) -> int:
    """Revoke every active passkey for a user (used during admin-issued recovery before a fresh one is registered)."""
    n = 0
    for cred in active_credentials(db, user.id):
        cred.revoked_at = utcnow()
        cred.revoked_by = actor.user_id
        n += 1
    if n:
        audit.record(db, user.organization_id, actor, "auth.passkeys_revoked_for_recovery", target_type="user",
                     target_id=user.id, target_label=user.email, metadata={"count": n})
    return n


def describe(c: WebAuthnCredential) -> dict:
    return {"id": str(c.id), "name": c.name, "created_at": c.created_at, "last_used_at": c.last_used_at,
            "synced": c.backed_up, "transports": (c.transports or {}).get("transports", []),
            "credential_id": bytes_to_base64url(c.credential_id)[:16] + "…"}
