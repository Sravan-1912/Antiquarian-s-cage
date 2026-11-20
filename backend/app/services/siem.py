"""SIEM / webhook egress: POST security alerts to a per-organization external destination (Splunk HEC, Elastic,
Datadog, or any JSON webhook), through a durable outbox delivered by the scheduler with retries — so a SIEM outage
never silently drops a security event.

The destination token is stored AES-256-GCM-encrypted and never returned to clients.
"""
from __future__ import annotations

import logging
import uuid
from datetime import timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import utcnow
from app.models import SecurityAlert, SiemDelivery, SiemDestination
from app.security import crypto

log = logging.getLogger("app.siem")
MAX_ATTEMPTS = 6
_SEV = ("low", "medium", "high", "critical")
_AAD = "siem-token"


def _rank(sev: str) -> int:
    return _SEV.index(sev) if sev in _SEV else 0


def destination(db: Session, org_id: uuid.UUID) -> SiemDestination | None:
    return db.scalar(select(SiemDestination).where(SiemDestination.organization_id == org_id))


def encrypt_token(token: str) -> str:
    return crypto.encrypt(token, _AAD)


def alert_payload(alert: SecurityAlert) -> dict:
    return {"source": "antiquarians-cage", "type": "security_alert", "rule": alert.rule_key, "kind": alert.kind,
            "severity": alert.severity, "title": alert.title, "description": alert.description,
            "device_id": str(alert.device_id) if alert.device_id else None,
            "detected_at": alert.detected_at.isoformat() if alert.detected_at else None,
            "evidence": alert.evidence or {}, "alert_id": str(alert.id)}


def enqueue(db: Session, org_id: uuid.UUID, payload: dict, severity: str = "low") -> bool:
    """Queue a security event for SIEM egress if the org has an enabled destination at/above its min severity.
    Does not commit — rides the caller's (alert-raising) transaction, so delivery is atomic with the alert."""
    dest = destination(db, org_id)
    if dest is None or not dest.enabled or _rank(severity) < _rank(dest.min_severity):
        return False
    db.add(SiemDelivery(id=uuid.uuid4(), organization_id=org_id, payload=payload))
    return True


def _post(dest: SiemDestination, payload: dict) -> None:
    headers = {"Content-Type": "application/json"}
    if dest.token_enc:
        headers[dest.auth_header] = crypto.decrypt(dest.token_enc, _AAD)  # full header value, verbatim
    httpx.post(dest.url, json=payload, headers=headers, timeout=10.0).raise_for_status()


def deliver_outbox(db: Session, batch: int = 20) -> tuple[int, int]:
    """Scheduler hook: deliver due SIEM events; exponential backoff (2,4,8… min); give up after MAX_ATTEMPTS."""
    sent = failed = 0
    due = db.scalars(select(SiemDelivery).where(SiemDelivery.status == "pending",
                                                SiemDelivery.next_attempt_at <= utcnow())
                     .order_by(SiemDelivery.created_at).limit(batch)).all()
    for d in due:
        dest = destination(db, d.organization_id)
        d.attempts += 1
        if dest is None or not dest.enabled:
            d.status, d.last_error = "failed", "no enabled SIEM destination"
            db.commit()
            failed += 1
            continue
        try:
            _post(dest, d.payload)
            d.status, d.sent_at, d.last_error = "sent", utcnow(), None
            dest.last_success_at, dest.last_error = utcnow(), None
            sent += 1
        except Exception as exc:  # noqa: BLE001 - any delivery failure is retried/backed off
            msg = str(exc)[:500]
            d.last_error = dest.last_error = msg
            if d.attempts >= MAX_ATTEMPTS:
                d.status = "failed"
                log.error("SIEM delivery permanently failed after %d attempts: %s", d.attempts, msg)
            else:
                d.next_attempt_at = utcnow() + timedelta(minutes=2 ** d.attempts)
            failed += 1
        db.commit()
    return sent, failed


def send_test(db: Session, org_id: uuid.UUID) -> dict:
    """Synchronously send a test event (for the config UI). Updates the destination's last_success/last_error."""
    dest = destination(db, org_id)
    if dest is None:
        return {"ok": False, "error": "no SIEM destination configured"}
    try:
        _post(dest, {"source": "antiquarians-cage", "type": "test", "message": "SIEM egress test"})
        dest.last_success_at, dest.last_error = utcnow(), None
        db.commit()
        return {"ok": True}
    except Exception as exc:  # noqa: BLE001
        dest.last_error = str(exc)[:500]
        db.commit()
        return {"ok": False, "error": str(exc)[:300]}
