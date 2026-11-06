"""Tamper-evident audit logging.

Each event's `hash` = SHA-256(prev_hash || canonical JSON of the event). `mac` = HMAC-SHA256(AUDIT_HMAC_KEY, hash).
The HMAC means someone with database write access but without the key cannot forge a consistent chain.
Limitations (see SECURITY.md): tail truncation is only detectable against an externally stored chain head.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utcnow
from app.models import AuditLog, Organization, User

GENESIS = "0" * 64


@dataclass
class Actor:
    type: str  # user | system | device
    user_id: uuid.UUID | None
    label: str
    ip: str | None = None

    @classmethod
    def from_user(cls, user: User, ip: str | None) -> "Actor":
        return cls("user", user.id, user.email, ip)

    @classmethod
    def system(cls, ip: str | None = None) -> "Actor":
        return cls("system", None, "system", ip)


def _canonical(e: AuditLog) -> bytes:
    payload = {
        "seq": e.seq,
        "org": str(e.organization_id),
        "actor_type": e.actor_type,
        "actor_user_id": str(e.actor_user_id) if e.actor_user_id else None,
        "actor_label": e.actor_label,
        "action": e.action,
        "target_type": e.target_type,
        "target_id": e.target_id,
        "target_label": e.target_label,
        "source_ip": e.source_ip,
        "result": e.result,
        "metadata": e.event_metadata,
        "ts": e.created_at.isoformat(timespec="microseconds"),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def _compute(prev_hash: str, e: AuditLog) -> tuple[str, str]:
    digest = hashlib.sha256(prev_hash.encode() + _canonical(e)).hexdigest()
    mac = hmac.new(get_settings().audit_key_bytes, digest.encode(), hashlib.sha256).hexdigest()
    return digest, mac


def record(
    db: Session,
    org_id: uuid.UUID,
    actor: Actor,
    action: str,
    *,
    target_type: str | None = None,
    target_id: object | None = None,
    target_label: str | None = None,
    result: str = "success",
    metadata: dict | None = None,
) -> AuditLog:
    """Append an audit event inside the caller's transaction (the caller commits)."""
    # Serialise chain appends per organisation (row lock on PostgreSQL; no-op on SQLite which is single-writer).
    db.execute(select(Organization.id).where(Organization.id == org_id).with_for_update())
    last = db.execute(
        select(AuditLog.seq, AuditLog.hash)
        .where(AuditLog.organization_id == org_id)
        .order_by(AuditLog.seq.desc())
        .limit(1)
    ).first()
    seq, prev = (last.seq + 1, last.hash) if last else (1, GENESIS)
    created = utcnow()
    entry = AuditLog(
        id=uuid.uuid4(),
        organization_id=org_id,
        seq=seq,
        actor_type=actor.type,
        actor_user_id=actor.user_id,
        actor_label=actor.label,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        target_label=target_label,
        source_ip=actor.ip,
        result=result,
        event_metadata=_scrub(metadata or {}),
        created_at=created,
        prev_hash=prev,
    )
    entry.hash, entry.mac = _compute(prev, entry)
    db.add(entry)
    db.flush()
    return entry


_SENSITIVE = {"password", "token", "secret", "code", "mfa_secret", "new_password", "current_password"}


def _scrub(meta: dict) -> dict:
    return {k: ("[redacted]" if k.lower() in _SENSITIVE else v) for k, v in meta.items()}


@dataclass
class VerificationResult:
    valid: bool
    checked: int
    first_invalid_seq: int | None
    reason: str | None
    head_seq: int | None
    head_hash: str | None
    verified_at: datetime


def verify_chain(db: Session, org_id: uuid.UUID, batch: int = 1000) -> VerificationResult:
    prev = GENESIS
    expected_seq = 1
    checked = 0
    last_seq: int | None = None
    offset_seq = 0
    while True:
        rows = db.scalars(
            select(AuditLog)
            .where(AuditLog.organization_id == org_id, AuditLog.seq > offset_seq)
            .order_by(AuditLog.seq)
            .limit(batch)
        ).all()
        if not rows:
            break
        for e in rows:
            if e.seq != expected_seq:
                return VerificationResult(False, checked, e.seq, f"sequence gap: expected {expected_seq}", last_seq, prev, utcnow())
            if e.prev_hash != prev:
                return VerificationResult(False, checked, e.seq, "previous-hash mismatch", last_seq, prev, utcnow())
            digest, mac = _compute(prev, e)
            if not hmac.compare_digest(digest, e.hash):
                return VerificationResult(False, checked, e.seq, "content hash mismatch (record modified)", last_seq, prev, utcnow())
            if not hmac.compare_digest(mac, e.mac):
                return VerificationResult(False, checked, e.seq, "HMAC mismatch (forged with wrong key)", last_seq, prev, utcnow())
            prev = e.hash
            last_seq = e.seq
            expected_seq += 1
            checked += 1
        offset_seq = rows[-1].seq
    return VerificationResult(True, checked, None, None, last_seq, prev if last_seq else None, utcnow())


def count(db: Session, org_id: uuid.UUID) -> int:
    return db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.organization_id == org_id)) or 0
