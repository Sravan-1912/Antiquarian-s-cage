"""Windows sign-in approved from the phone (Phase 10). See documentation/12-windows-phone-unlock.md.

Setup  (kind="enroll"): the credential provider verifies the typed Windows password, encrypts it locally under a
        fresh random key K and sends K (via the local agent) here. K is stored *pending* and becomes active only when
        the device's assigned person approves "Set up phone sign-in" on their phone.
Unlock (kind="unlock"): the provider asks for approval; after a biometric-signed approval with the right number the
        device (and only that device, over its authenticated agent channel) receives K once, decrypts the password
        locally and hands it to Windows.

Who approves: the person the device is assigned to (Endpoint → Assigned to → that employee's workspace account).
Windows accounts are bound by SID, so a key enrolled for one account never unlocks another.
"""
from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import utcnow
from app.models import Device, Employee, PhoneAuthenticator, PhoneLoginRequest, User, WindowsUnlockKey
from app.security import crypto
from app.security.tokens import constant_time_equals, hash_token, new_token
from app.services import audit, phone_auth
from app.services.audit import Actor
from app.services.auth import ClientInfo


class UnlockError(Exception):
    def __init__(self, message: str, status: int = 409, code: str = "unavailable"):
        super().__init__(message)
        self.message, self.status, self.code = message, status, code


def _aad(device_id: uuid.UUID, sid: str) -> str:
    return f"winunlock|{device_id}|{sid}"


def approver(db: Session, device: Device) -> User:
    """The Cage user whose phone must approve sign-ins on this device."""
    if device.status != "active":
        raise UnlockError("This device is not active in Antiquarian's Cage.", 403, "device_inactive")
    emp = db.get(Employee, device.employee_id) if device.employee_id else None
    if emp is None:
        raise UnlockError("This device is not assigned to anyone, so no phone can approve sign-in.", 409, "unassigned")
    if emp.status != "active" or emp.user_id is None:
        raise UnlockError(f"{emp.full_name} has no active workspace account.", 409, "no_account")
    user = db.get(User, emp.user_id)
    if user is None or user.status != "active":
        raise UnlockError(f"{emp.full_name}'s account is not active.", 409, "no_account")
    phones = db.scalar(select(func.count()).select_from(PhoneAuthenticator).where(
        PhoneAuthenticator.user_id == user.id, PhoneAuthenticator.revoked_at.is_(None))) or 0
    if not phones:
        raise UnlockError(f"{user.email} has not paired a phone yet (console → Account → Security).", 409, "no_phone")
    return user


def _active_key(db: Session, device: Device, sid: str, user_id: uuid.UUID) -> WindowsUnlockKey | None:
    return db.scalar(select(WindowsUnlockKey).where(
        WindowsUnlockKey.device_id == device.id, WindowsUnlockKey.windows_sid == sid,
        WindowsUnlockKey.user_id == user_id, WindowsUnlockKey.status == "active"))


@dataclass
class Started:
    request_id: uuid.UUID
    number: int
    secret: str
    expires_at: object
    approver: str


def start(db: Session, device: Device, *, kind: str, windows_user: str, sid: str, key_b64: str | None,
          ip: str | None) -> Started:
    if kind not in ("unlock", "enroll"):
        raise UnlockError("Unknown request kind.", 400, "bad_request")
    if not sid.startswith("S-1-5-") or len(sid) > 184:
        raise UnlockError("Invalid Windows account SID.", 400, "bad_request")
    user = approver(db, device)
    key_row = None
    if kind == "unlock":
        if _active_key(db, device, sid, user.id) is None:
            raise UnlockError("Phone sign-in is not set up for this Windows account on this device.", 404, "not_enrolled")
    else:
        try:
            raw = base64.b64decode(key_b64 or "", validate=True)
        except ValueError:
            raw = b""
        if len(raw) != 32:
            raise UnlockError("Setup key must be 32 random bytes.", 400, "bad_request")
        key_row = WindowsUnlockKey(id=uuid.uuid4(), organization_id=device.organization_id, device_id=device.id,
                                   user_id=user.id, windows_sid=sid, windows_user=windows_user[:256],
                                   key_enc=crypto.encrypt(key_b64, _aad(device.id, sid)))
    secret = new_token(32)
    r = PhoneLoginRequest(
        id=uuid.uuid4(), organization_id=device.organization_id, user_id=user.id,
        purpose="windows" if kind == "unlock" else "windows_enroll",
        browser_secret_hash=hash_token(secret), challenge=new_token(24), number=__import__("secrets").randbelow(90) + 10,
        client_ip=ip, user_agent=f"Windows sign-in on {device.hostname}"[:300],
        context={"device": device.display_name, "device_id": str(device.id), "windows_user": windows_user[:256],
                 "sid": sid, "kind": kind},
        expires_at=utcnow() + phone_auth.REQUEST_TTL)
    db.add(r)
    db.flush()
    if key_row is not None:
        key_row.request_id = r.id
        db.add(key_row)
    audit.record(db, device.organization_id, Actor("device", None, device.hostname, ip),
                 "windows.unlock_requested" if kind == "unlock" else "windows.setup_requested",
                 target_type="user", target_id=user.id, target_label=user.email,
                 metadata={"device": device.display_name, "windows_user": windows_user[:256], "request_id": str(r.id)})
    return Started(r.id, r.number, secret, r.expires_at, user.email)


def status(db: Session, device: Device, request_id: uuid.UUID, secret: str, ip: str | None) -> dict:
    r = db.scalar(select(PhoneLoginRequest).where(PhoneLoginRequest.id == request_id).with_for_update())
    if (r is None or r.purpose not in ("windows", "windows_enroll") or r.context.get("device_id") != str(device.id)
            or not constant_time_equals(hash_token(secret), r.browser_secret_hash)):
        raise UnlockError("Unknown request.", 404, "unknown")
    if r.status == "pending" and r.expires_at <= utcnow():
        r.status = "expired"
    if r.status != "approved":
        return {"status": r.status}
    user = db.get(User, r.user_id)
    actor = Actor("device", None, device.hostname, ip)
    r.status = "consumed"
    if r.purpose == "windows_enroll":
        k = db.scalar(select(WindowsUnlockKey).where(WindowsUnlockKey.request_id == r.id, WindowsUnlockKey.status == "pending"))
        if k is None:
            raise UnlockError("Setup request has no pending key.", 409, "unknown")
        now = utcnow()
        for old in db.scalars(select(WindowsUnlockKey).where(
                WindowsUnlockKey.device_id == device.id, WindowsUnlockKey.windows_sid == k.windows_sid,
                WindowsUnlockKey.status == "active")):
            old.status, old.revoked_at = "revoked", now
        k.status, k.activated_at = "active", now
        audit.record(db, device.organization_id, actor, "windows.setup_completed", target_type="user",
                     target_id=user.id, target_label=user.email,
                     metadata={"device": device.display_name, "windows_user": k.windows_user})
        return {"status": "enrolled"}
    sid = r.context.get("sid", "")
    k = _active_key(db, device, sid, user.id)
    if k is None:
        raise UnlockError("Phone sign-in was removed for this account.", 404, "not_enrolled")
    k.last_used_at = utcnow()
    audit.record(db, device.organization_id, actor, "windows.unlock_released", target_type="user", target_id=user.id,
                 target_label=user.email, metadata={"device": device.display_name, "windows_user": k.windows_user})
    return {"status": "approved", "key": crypto.decrypt(k.key_enc, _aad(device.id, sid))}


def revoke(db: Session, k: WindowsUnlockKey, actor: Actor) -> None:
    if k.status != "revoked":
        k.status, k.revoked_at = "revoked", utcnow()
        audit.record(db, k.organization_id, actor, "windows.unlock_removed", target_type="device",
                     target_id=k.device_id, target_label=k.windows_user)


def describe(db: Session, k: WindowsUnlockKey) -> dict:
    d = db.get(Device, k.device_id)
    u = db.get(User, k.user_id)
    return {"id": str(k.id), "device_id": str(k.device_id), "device": d.display_name if d else None,
            "windows_user": k.windows_user, "approver": u.email if u else None, "status": k.status,
            "activated_at": k.activated_at, "last_used_at": k.last_used_at}
