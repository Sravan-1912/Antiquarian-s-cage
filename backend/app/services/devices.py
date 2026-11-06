"""Endpoint lifecycle: enrollment, authentication of agent requests, heartbeats, inventory, admin operations."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utcnow
from app.models import (
    AgentRequestNonce, CommandJob, Device, DeviceCertificate, DeviceEvent, DeviceHeartbeat, DeviceInventory, Employee,
    EnrollmentToken,
)
from app.schemas.endpoints import EnrollRequest, HeartbeatRequest, InventoryRequest
from app.security import pki
from app.security.tokens import hash_token
from app.services import audit, notifications
from app.services.audit import Actor


class DeviceError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


def connectivity(device: Device, now: datetime | None = None) -> str:
    """Online is derived only from authenticated heartbeats — never from the record merely existing."""
    if device.last_heartbeat_at is None:
        return "never"
    now = now or utcnow()
    threshold = timedelta(seconds=get_settings().offline_threshold_seconds)
    return "online" if now - device.last_heartbeat_at <= threshold else "offline"


def device_actor(device: Device, ip: str | None) -> Actor:
    return Actor("device", None, f"device:{device.hostname}", ip)


def _event(db: Session, device: Device, kind: str, details: dict, actor_id: uuid.UUID | None = None) -> None:
    db.add(DeviceEvent(device_id=device.id, kind=kind, details=details, actor_id=actor_id))


def _normalise_token(raw: str) -> str:
    # Tolerate case, spaces and dashes when an administrator types the token by hand.
    return "".join(ch for ch in raw.upper() if ch.isalnum())


# ------------------------------------------------------------------------------------------------ tokens
def create_enrollment_token(db: Session, org_id: uuid.UUID, actor: Actor, *, label: str,
                            employee_id: uuid.UUID | None, minutes: int) -> tuple[EnrollmentToken, str]:
    minutes = min(minutes, get_settings().enrollment_token_max_minutes)
    raw = pki.new_enrollment_secret()
    tok = EnrollmentToken(organization_id=org_id, token_hash=hash_token(_normalise_token(raw)), label=label,
                          employee_id=employee_id, created_by=actor.user_id,
                          expires_at=utcnow() + timedelta(minutes=minutes))
    db.add(tok)
    db.flush()
    audit.record(db, org_id, actor, "device.enrollment_token_created", target_type="enrollment_token",
                 target_id=tok.id, target_label=label,
                 metadata={"expires_in_minutes": minutes, "employee_id": str(employee_id) if employee_id else None})
    return tok, raw


def token_state(tok: EnrollmentToken) -> str:
    if tok.revoked_at:
        return "revoked"
    if tok.used_at:
        return "used"
    if tok.expires_at < utcnow():
        return "expired"
    return "active"


# ------------------------------------------------------------------------------------------------ enrollment
def enroll(db: Session, req: EnrollRequest, source_ip: str | None) -> tuple[Device, pki.IssuedCert]:
    tok = db.scalar(select(EnrollmentToken).where(EnrollmentToken.token_hash == hash_token(_normalise_token(req.token)))
                    .with_for_update())
    if tok is None or token_state(tok) != "active":
        raise DeviceError("Enrollment token is invalid, expired or already used", 401)

    device = Device(
        organization_id=tok.organization_id, employee_id=tok.employee_id, display_name=req.hostname,
        hostname=req.hostname, agent_version=req.agent_version, status="active", last_seen_ip=source_ip,
        os_name=req.os.name if req.os else None, os_version=req.os.version if req.os else None,
        os_build=req.os.build if req.os else None, reported_ip_addresses={}, reported_mac_addresses={},
    )
    db.add(device)
    db.flush()
    try:
        issued = pki.sign_csr(req.csr_pem, device.id)
    except pki.PKIError as exc:
        db.rollback()
        raise DeviceError(str(exc), 400) from exc

    db.add(DeviceCertificate(device_id=device.id, serial=issued.serial, fingerprint_sha256=issued.fingerprint,
                             public_key_pem=issued.public_key_pem, certificate_pem=issued.certificate_pem,
                             not_before=issued.not_before, not_after=issued.not_after, status="active"))
    tok.used_at = utcnow()
    tok.used_by_device_id = device.id
    if device.employee_id:
        emp = db.get(Employee, device.employee_id)
        if emp:
            emp.enrollment_status = "enrolled"
    _event(db, device, "enrolled", {"token_label": tok.label, "source_ip": source_ip,
                                    "cert_fingerprint": issued.fingerprint})
    audit.record(db, tok.organization_id, device_actor(device, source_ip), "device.enrolled", target_type="device",
                 target_id=device.id, target_label=device.hostname,
                 metadata={"token_id": str(tok.id), "agent_version": req.agent_version,
                           "cert_serial": issued.serial})
    notifications.notify_users(
        db, tok.organization_id, notifications.users_with_permission(db, tok.organization_id, "devices:manage"),
        kind="device.enrolled", title=f"New endpoint enrolled: {device.hostname}",
        body=f"Enrolled with token “{tok.label}” from {source_ip}.", link=f"/endpoints/{device.id}",
    )
    db.commit()
    return device, issued


# ------------------------------------------------------------------------------------------------ agent auth
def authenticate_agent(db: Session, *, device_id: str, timestamp: str, nonce: str, signature: str, method: str,
                       path: str, body: bytes, proxy_fingerprint: str | None) -> tuple[Device, DeviceCertificate]:
    s = get_settings()
    generic = DeviceError("Agent authentication failed", 401)
    try:
        did = uuid.UUID(device_id)
        ts = datetime.fromisoformat(timestamp)
    except ValueError:
        raise generic
    if ts.tzinfo is None or not (16 <= len(nonce) <= 64) or not nonce.isalnum():
        raise generic
    now = utcnow()
    if abs((now - ts).total_seconds()) > s.agent_signature_window_seconds:
        raise DeviceError("Request timestamp outside the allowed window (check the endpoint clock)", 401)

    device = db.get(Device, did)
    if device is None or device.status in ("revoked", "unenrolled"):
        raise generic
    cert = db.scalar(select(DeviceCertificate).where(DeviceCertificate.device_id == did,
                                                     DeviceCertificate.status == "active")
                     .order_by(DeviceCertificate.created_at.desc()).limit(1))
    if cert is None or cert.not_after < now:
        raise generic
    if s.agent_require_mtls:
        if not proxy_fingerprint or proxy_fingerprint.lower().replace(":", "") != cert.fingerprint_sha256:
            raise generic
    if not pki.verify_signature(cert.public_key_pem, pki.canonical_request(method, path, timestamp, nonce, body),
                                signature):
        raise generic

    db.execute(delete(AgentRequestNonce).where(AgentRequestNonce.expires_at < now))
    db.add(AgentRequestNonce(device_id=did, nonce=nonce,
                             expires_at=now + timedelta(seconds=2 * s.agent_signature_window_seconds)))
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise DeviceError("Replayed request rejected", 401)
    return device, cert


# ------------------------------------------------------------------------------------------------ agent data
def record_heartbeat(db: Session, device: Device, cert: DeviceCertificate, req: HeartbeatRequest,
                     source_ip: str | None) -> dict:
    s = get_settings()
    now = utcnow()
    was = connectivity(device, now)
    device.last_heartbeat_at = now
    device.last_seen_ip = source_ip
    if req.agent_version != device.agent_version:
        _event(db, device, "agent_version_changed", {"from": device.agent_version, "to": req.agent_version})
        device.agent_version = req.agent_version
    db.add(DeviceHeartbeat(device_id=device.id, received_at=now, source_ip=source_ip,
                           agent_version=req.agent_version, uptime_seconds=req.uptime_seconds))
    if was == "offline":
        _event(db, device, "came_online", {"source_ip": source_ip})
    db.flush()
    response = {
        "status": device.status,
        "heartbeat_interval_seconds": s.heartbeat_interval_seconds,
        "inventory_interval_seconds": s.inventory_interval_seconds,
        "certificate_renewal_due": cert.not_after - now < timedelta(days=s.device_cert_renew_before_days),
        "server_time": now,
        "jobs_pending": bool(db.scalar(select(func.count()).select_from(CommandJob).where(
            CommandJob.device_id == device.id, CommandJob.status.in_(("queued", "revoked"))))),
    }
    db.commit()
    return response


def record_inventory(db: Session, device: Device, req: InventoryRequest) -> None:
    if req.hostname.lower() != device.hostname.lower():
        _event(db, device, "hostname_changed", {"from": device.hostname, "to": req.hostname})
        device.hostname = req.hostname
    device.os_name, device.os_version, device.os_build = req.os.name, req.os.version, req.os.build
    device.manufacturer, device.model = req.hardware.manufacturer, req.hardware.model
    device.serial_number = req.hardware.serial_number
    device.agent_version = req.agent_version
    device.reported_ip_addresses = {"addresses": sorted({ip for n in req.network_interfaces for ip in n.ipv4})}
    device.reported_mac_addresses = {"addresses": sorted({n.mac_address.upper().replace("-", ":")
                                                          for n in req.network_interfaces if n.mac_address})}
    device.last_inventory_at = utcnow()
    inv = DeviceInventory(
        device_id=device.id, agent_collected_at=req.collected_at, cpu=req.cpu.model_dump(),
        memory_bytes=req.memory_bytes, disks={"items": [d.model_dump() for d in req.disks]},
        network_interfaces={"items": [n.model_dump() for n in req.network_interfaces]},
        security={k: v.model_dump() for k, v in req.security.items()} | (
            {"_collection_errors": {"state": "unknown", "detail": "; ".join(req.collection_errors)[:512], "data": {}}}
            if req.collection_errors else {}),
        os=req.os.model_dump(),
    )
    db.add(inv)
    db.flush()
    _usb_events(db, device, req)
    from app.services import compliance
    compliance.evaluate(db, device, inv)
    db.commit()


def _usb_events(db: Session, device: Device, req: InventoryRequest) -> None:
    """Record USB storage connections/disconnections by diffing consecutive inventories (reported data)."""
    usb = req.security.get("usb_storage")
    if usb is None:
        return
    current = {k: v for k, v in (usb.data or {}).items() if k.startswith("dev")}
    prev_inv = db.scalar(select(DeviceInventory).where(DeviceInventory.device_id == device.id)
                         .order_by(DeviceInventory.collected_at.desc()).offset(1).limit(1))
    prev = {k: v for k, v in ((prev_inv.security or {}).get("usb_storage", {}).get("data") or {}).items()
            if k.startswith("dev")} if prev_inv else {}
    for name in set(current.values()) - set(prev.values()):
        _event(db, device, "usb_storage_connected", {"device": str(name)[:200]})
        from app.services import alerts
        alerts.on_usb_connected(db, device, str(name)[:200])
    for name in set(prev.values()) - set(current.values()):
        _event(db, device, "usb_storage_disconnected", {"device": str(name)[:200]})


def renew_certificate(db: Session, device: Device, old: DeviceCertificate, csr_pem: str,
                      source_ip: str | None) -> pki.IssuedCert:
    if device.status != "active":
        raise DeviceError("Device is not active", 403)
    try:
        issued = pki.sign_csr(csr_pem, device.id)
    except pki.PKIError as exc:
        raise DeviceError(str(exc), 400) from exc
    old.status = "superseded"
    db.add(DeviceCertificate(device_id=device.id, serial=issued.serial, fingerprint_sha256=issued.fingerprint,
                             public_key_pem=issued.public_key_pem, certificate_pem=issued.certificate_pem,
                             not_before=issued.not_before, not_after=issued.not_after, status="active"))
    _event(db, device, "certificate_renewed", {"old_serial": old.serial, "new_serial": issued.serial})
    audit.record(db, device.organization_id, device_actor(device, source_ip), "device.certificate_renewed",
                 target_type="device", target_id=device.id, target_label=device.hostname,
                 metadata={"old_serial": old.serial, "new_serial": issued.serial})
    db.commit()
    return issued


# ------------------------------------------------------------------------------------------------ admin ops
def revoke_certificates(db: Session, device: Device, reason: str) -> int:
    return db.execute(update(DeviceCertificate)
                      .where(DeviceCertificate.device_id == device.id, DeviceCertificate.status == "active")
                      .values(status="revoked", revoked_at=utcnow(), revoked_reason=reason[:64])).rowcount or 0


TRANSITIONS = {
    "suspend": ({"active"}, "suspended", "device.suspended"),
    "reactivate": ({"suspended"}, "active", "device.reactivated"),
    "revoke": ({"active", "suspended"}, "revoked", "device.credentials_revoked"),
    "unenroll": ({"active", "suspended", "revoked"}, "unenrolled", "device.unenrolled"),
}


def transition(db: Session, device: Device, op: str, reason: str, actor: Actor) -> Device:
    allowed, to, action = TRANSITIONS[op]
    if device.status not in allowed:
        raise DeviceError(f"Cannot {op} a device whose status is '{device.status}'", 409)
    before = device.status
    device.status = to
    revoked = revoke_certificates(db, device, op) if to in ("revoked", "unenrolled") else 0
    if to == "unenrolled" and device.employee_id:
        _refresh_employee_enrollment(db, device.employee_id, exclude=device.id)
    details = {"from": before, "to": to, "reason": reason, "certificates_revoked": revoked}
    _event(db, device, op, details, actor.user_id)
    audit.record(db, device.organization_id, actor, action, target_type="device", target_id=device.id,
                 target_label=device.hostname, metadata=details)
    db.commit()
    return device


def _refresh_employee_enrollment(db: Session, employee_id: uuid.UUID, exclude: uuid.UUID | None = None) -> None:
    emp = db.get(Employee, employee_id)
    if emp is None:
        return
    q = select(Device.id).where(Device.employee_id == employee_id, Device.status.in_(("active", "suspended")))
    if exclude:
        q = q.where(Device.id != exclude)
    emp.enrollment_status = "enrolled" if db.scalar(q.limit(1)) else "not_enrolled"


def assign(db: Session, device: Device, changes: dict, actor: Actor) -> Device:
    diff = {}
    for key in ("display_name", "employee_id", "support_owner_id"):
        if key in changes and getattr(device, key) != changes[key]:
            diff[key] = {"from": str(getattr(device, key)) if getattr(device, key) else None,
                         "to": str(changes[key]) if changes[key] else None}
    if not diff:
        return device
    old_emp = device.employee_id
    for k in diff:
        setattr(device, k, changes[k])
    db.flush()
    if "employee_id" in diff:
        if old_emp:
            _refresh_employee_enrollment(db, old_emp)
        if device.employee_id:
            _refresh_employee_enrollment(db, device.employee_id)
    _event(db, device, "updated", diff, actor.user_id)
    audit.record(db, device.organization_id, actor, "device.updated", target_type="device", target_id=device.id,
                 target_label=device.hostname, metadata={"changes": diff})
    db.commit()
    return device


def purge_old_heartbeats(db: Session) -> int:
    cutoff = utcnow() - timedelta(days=get_settings().heartbeat_retention_days)
    n = db.execute(delete(DeviceHeartbeat).where(DeviceHeartbeat.received_at < cutoff)).rowcount or 0
    db.commit()
    return n
