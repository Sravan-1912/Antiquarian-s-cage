"""Device OS patch status: store each endpoint's latest pending-update snapshot (by severity), reboot-pending flag
and last-patched date, and roll it up into a fleet "patch scorecard". Agent-reported, informational — counts may be
null when the OS can't supply them (e.g. Windows Update offline)."""
from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import utcnow
from app.models import Device, DevicePatchStatus


def record(db: Session, device_id: uuid.UUID, data: dict) -> None:
    """Upsert a device's latest patch-status snapshot."""
    row = db.execute(
        select(DevicePatchStatus).where(DevicePatchStatus.device_id == device_id)
    ).scalar_one_or_none()
    if row is None:
        row = DevicePatchStatus(device_id=device_id)
        db.add(row)
    row.pending_total = data.get("pending_total")
    row.pending_critical = data.get("pending_critical")
    row.pending_important = data.get("pending_important")
    row.reboot_pending = bool(data.get("reboot_pending"))
    row.last_patched = (data.get("last_patched") or None)
    row.checked_at = utcnow()
    db.commit()


def device_status(db: Session, device_id: uuid.UUID) -> dict | None:
    row = db.execute(
        select(DevicePatchStatus).where(DevicePatchStatus.device_id == device_id)
    ).scalar_one_or_none()
    if row is None:
        return None
    return {
        "pending_total": row.pending_total,
        "pending_critical": row.pending_critical,
        "pending_important": row.pending_important,
        "reboot_pending": row.reboot_pending,
        "last_patched": row.last_patched,
        "checked_at": row.checked_at.isoformat() if row.checked_at else None,
    }


def fleet_summary(db: Session, device_ids: list[uuid.UUID]) -> dict:
    """Aggregate patch posture across the given (visible) devices for the scorecard.

    Returns reporting counts, totals of pending updates by severity, and how many endpoints are up to date, have
    critical updates pending, or are awaiting a reboot. Devices that have never reported are counted as not reporting.
    """
    total_devices = len(device_ids)
    if not device_ids:
        return {"devices": 0, "reporting": 0, "up_to_date": 0, "with_critical": 0,
                "reboot_pending": 0, "pending_total": 0, "pending_critical": 0, "pending_important": 0}
    rows = db.execute(
        select(DevicePatchStatus).where(DevicePatchStatus.device_id.in_(device_ids))
    ).scalars().all()
    reporting = len(rows)
    up_to_date = sum(1 for r in rows if (r.pending_total or 0) == 0 and not r.reboot_pending)
    with_critical = sum(1 for r in rows if (r.pending_critical or 0) > 0)
    reboot_pending = sum(1 for r in rows if r.reboot_pending)
    pending_total = sum((r.pending_total or 0) for r in rows)
    pending_critical = sum((r.pending_critical or 0) for r in rows)
    pending_important = sum((r.pending_important or 0) for r in rows)
    return {
        "devices": total_devices,
        "reporting": reporting,
        "up_to_date": up_to_date,
        "with_critical": with_critical,
        "reboot_pending": reboot_pending,
        "pending_total": pending_total,
        "pending_critical": pending_critical,
        "pending_important": pending_important,
    }
