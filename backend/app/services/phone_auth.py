"""Phone approval sign-in ("Approve on your phone").

Pairing
  A signed-in user asks for a pairing code (QR, single use, 5 minutes). The Cage Authenticator app creates a key
  pair inside the phone's secure hardware with "user authentication required" (fingerprint/face for every use), and
  proves possession by signing `CAGE-PAIR-V1|<token>|<sha256(public key)>` - which already requires a biometric match.

Sign-in
  The browser starts a request for an email address and receives a request id, a 2-digit number and an HttpOnly
  browser secret (so only *that* browser can collect the session). The app lists pending requests (authenticated by a
  per-phone poll secret, no biometric) and shows three numbers; the user taps the one the browser shows and confirms
  with fingerprint/face, which signs `CAGE-APPROVE-V1|<request>|<challenge>|<decision>|<number>`. The server checks
  the signature with the stored public key, the number, expiry and single use, then the browser's next poll receives
  the session (amr: hwk + user + mfa + phone: possession of hardware key + biometric = two factors).

Decoys
  Unknown, disabled or unpaired accounts get a normal-looking request that can never be approved, so the endpoint
  does not reveal which emails exist or have a phone paired.
"""
from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utcnow
from app.models import Organization, PhoneAuthenticator, PhoneLoginRequest, PhonePairing, User
from app.security.tokens import constant_time_equals, hash_token, new_token
from app.services import audit
from app.services.audit import Actor
from app.services.auth import ClientInfo

PAIRING_TTL = timedelta(minutes=5)
REQUEST_TTL = timedelta(minutes=2)  # used by the Windows-unlock flow (app/api/remote.py / unlock) to set request expiry
MAX_AUTHENTICATORS = 3


class PhoneAuthError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message, self.status = message, status


# --------------------------------------------------------------------------------------------- crypto
def _load_public_key(pem: str, alg: str):
    try:
        key = serialization.load_pem_public_key(pem.encode())
    except ValueError as exc:
        raise PhoneAuthError("Public key is not valid PEM") from exc
    if alg == "ES256":
        if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
            raise PhoneAuthError("ES256 requires a P-256 key")
    elif alg == "RS256":
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
            raise PhoneAuthError("RS256 requires an RSA key of at least 2048 bits")
    else:
        raise PhoneAuthError("Unsupported key algorithm")
    return key


def _verify(pem: str, alg: str, signature_b64: str, message: bytes) -> bool:
    key = _load_public_key(pem, alg)
    try:
        sig = base64.b64decode(signature_b64, validate=True)
        if alg == "ES256":
            key.verify(sig, message, ec.ECDSA(hashes.SHA256()))
        else:
            key.verify(sig, message, padding.PKCS1v15(), hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False


def _key_fingerprint(pem: str) -> str:
    der = serialization.load_pem_public_key(pem.encode()).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def pair_message(token: str, public_key_pem: str) -> bytes:
    return f"CAGE-PAIR-V1|{token}|{_key_fingerprint(public_key_pem)}".encode()


def approve_message(request_id: str, challenge: str, decision: str, number: int) -> bytes:
    return f"CAGE-APPROVE-V1|{request_id}|{challenge}|{decision}|{number}".encode()


# --------------------------------------------------------------------------------------------- pairing
def start_pairing(db: Session, user: User, actor: Actor) -> tuple[str, dict]:
    active = db.scalar(select(func.count()).select_from(PhoneAuthenticator).where(
        PhoneAuthenticator.user_id == user.id, PhoneAuthenticator.revoked_at.is_(None))) or 0
    if active >= MAX_AUTHENTICATORS:
        raise PhoneAuthError(f"At most {MAX_AUTHENTICATORS} phones can be paired; remove one first.", 409)
    raw = "cgp_" + new_token(24)
    p = PhonePairing(user_id=user.id, token_hash=hash_token(raw), expires_at=utcnow() + PAIRING_TTL)
    db.add(p)
    audit.record(db, user.organization_id, actor, "phone.pairing_started", target_type="user", target_id=user.id,
                 target_label=user.email)
    payload = {"v": 1, "type": "cage-pair", "server": (get_settings().phone_api_base_url or get_settings().public_base_url).rstrip("/"), "token": raw,
               "account": user.email}
    return raw, {"payload": payload, "expires_at": p.expires_at}


def complete_pairing(db: Session, token: str, public_key_pem: str, key_alg: str, name: str, platform: str,
                     signature: str, client: ClientInfo) -> tuple[PhoneAuthenticator, str]:
    p = db.scalar(select(PhonePairing).where(PhonePairing.token_hash == hash_token(token)).with_for_update())
    if p is None or p.used_at is not None or p.expires_at < utcnow():
        raise PhoneAuthError("This pairing code is invalid or has expired. Create a new one in the console.", 400)
    _load_public_key(public_key_pem, key_alg)
    if not _verify(public_key_pem, key_alg, signature, pair_message(token, public_key_pem)):
        raise PhoneAuthError("Pairing signature is invalid.", 400)
    user = db.get(User, p.user_id)
    if user is None or user.status != "active":
        raise PhoneAuthError("This account cannot pair a phone.", 403)
    p.used_at = utcnow()
    poll_secret = new_token(32)
    a = PhoneAuthenticator(id=uuid.uuid4(), organization_id=user.organization_id, user_id=user.id,
                           name=(name or "Phone").strip()[:80], platform=platform, key_alg=key_alg,
                           public_key_pem=public_key_pem, poll_secret_hash=hash_token(poll_secret))
    db.add(a)
    audit.record(db, user.organization_id, Actor("user", user.id, user.email, client.ip), "phone.paired",
                 target_type="phone_authenticator", target_id=a.id, target_label=a.name,
                 metadata={"platform": platform, "alg": key_alg})
    from app.services import notifications
    notifications.notify_users(db, user.organization_id, [user], kind="auth.phone_paired", severity="medium",
                               title="A phone was paired with your account",
                               body=f"{a.name} can now approve sign-ins. If this was not you, remove it and change your password.",
                               link="/account/security")
    return a, poll_secret


def _authenticator(db: Session, authenticator_id: uuid.UUID, poll_secret: str) -> PhoneAuthenticator:
    a = db.get(PhoneAuthenticator, authenticator_id)
    if a is None or a.revoked_at is not None or not constant_time_equals(hash_token(poll_secret), a.poll_secret_hash):
        raise PhoneAuthError("This phone is not paired (it may have been removed).", 401)
    user = db.get(User, a.user_id)
    if user is None or user.status != "active":
        raise PhoneAuthError("This phone is not paired (it may have been removed).", 401)
    return a


def revoke(db: Session, a: PhoneAuthenticator, actor: Actor) -> None:
    if a.revoked_at is None:
        a.revoked_at = utcnow()
        audit.record(db, a.organization_id, actor, "phone.removed", target_type="phone_authenticator",
                     target_id=a.id, target_label=a.name)


def describe(a: PhoneAuthenticator) -> dict:
    return {"id": str(a.id), "name": a.name, "platform": a.platform, "key_alg": a.key_alg,
            "created_at": a.created_at, "last_used_at": a.last_used_at}


# ----------------------------------------------------------- phone approval (Windows unlock + the authenticator app)
def _choices(r: PhoneLoginRequest) -> list[int]:
    """Three distinct numbers including the right one, in an order derived from the challenge (stable per request)."""
    seed = int.from_bytes(hashlib.sha256(r.challenge.encode()).digest()[:8], "big")
    others: list[int] = []
    n = seed
    while len(others) < 2:
        n = (n * 6364136223846793005 + 1442695040888963407) % (1 << 64)
        cand = 10 + n % 90
        if cand != r.number and cand not in others:
            others.append(cand)
    out = others + [r.number]
    pos = seed % 3
    out[pos], out[2] = out[2], out[pos]
    return out


def pending(db: Session, authenticator_id: uuid.UUID, poll_secret: str) -> list[dict]:
    a = _authenticator(db, authenticator_id, poll_secret)
    now = utcnow()
    rows = db.scalars(select(PhoneLoginRequest).where(
        PhoneLoginRequest.user_id == a.user_id, PhoneLoginRequest.status == "pending",
        PhoneLoginRequest.expires_at > now).order_by(PhoneLoginRequest.created_at.desc()).limit(5)).all()
    org = db.get(Organization, a.organization_id)
    return [{"id": str(r.id), "challenge": r.challenge, "purpose": r.purpose, "choices": _choices(r),
             "created_at": r.created_at, "expires_at": r.expires_at, "ip": r.client_ip,
             "client": r.user_agent, "context": r.context, "organization": org.name if org else None}
            for r in rows]


def decide(db: Session, authenticator_id: uuid.UUID, poll_secret: str, request_id: uuid.UUID, decision: str,
           number: int, signature: str, client: ClientInfo) -> str:
    a = _authenticator(db, authenticator_id, poll_secret)
    r = db.scalar(select(PhoneLoginRequest).where(PhoneLoginRequest.id == request_id).with_for_update())
    if r is None or r.user_id != a.user_id:
        raise PhoneAuthError("Request not found.", 404)
    if r.status != "pending" or r.expires_at <= utcnow():
        raise PhoneAuthError("This request has expired or was already answered.", 409)
    if decision not in ("approve", "deny"):
        raise PhoneAuthError("Invalid decision.")
    if not _verify(a.public_key_pem, a.key_alg, signature, approve_message(str(r.id), r.challenge, decision, number)):
        raise PhoneAuthError("Signature check failed - confirm with your fingerprint or face again.", 400)
    user = db.get(User, a.user_id)
    actor = Actor("user", user.id, user.email, client.ip)
    r.decided_at, r.authenticator_id = utcnow(), a.id
    a.last_used_at = utcnow()
    from app.services import alerts
    if decision == "deny" or number != r.number:
        r.status = "denied"
        r.reason = "user_denied" if decision == "deny" else "number_mismatch"
        audit.record(db, user.organization_id, actor, "phone.request_denied", target_type="phone_login_request",
                     target_id=r.id, result="failure", metadata={"reason": r.reason, "ip": r.client_ip,
                                                                   "purpose": r.purpose})
        alerts.raise_alert(db, user.organization_id, "phone_approval_refused", severity="high",
                           dedup_key=f"phone_refused:{user.id}", subject_user_id=user.id, subject_label=user.email,
                           title=f"Sign-in approval refused on {user.email}'s phone",
                           description=("The user denied a sign-in request" if decision == "deny" else
                                        "The user picked a different number than the requesting screen showed")
                                       + f" (request from {r.client_ip or 'unknown address'}). Someone else may "
                                         "know this account's email and be trying to sign in.",
                           evidence={"request_id": str(r.id), "ip": r.client_ip, "client": r.user_agent,
                                     "reason": r.reason})
        return "denied"
    r.status = "approved"
    audit.record(db, user.organization_id, actor, "phone.request_approved", target_type="phone_login_request",
                 target_id=r.id, metadata={"ip": r.client_ip, "purpose": r.purpose, "phone": a.name})
    return "approved"
