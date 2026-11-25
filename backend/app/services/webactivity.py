"""Aggregated per-domain web activity: store each device's latest domain → visit-count snapshot, and roll it up
into a fleet-wide "Top websites" view. Only domains and counts are kept — never full URLs."""
from __future__ import annotations

import uuid

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.database import utcnow
from app.models import DeviceSiteVisit


def record(db: Session, device_id: uuid.UUID, sites: list[dict]) -> None:
    """Replace a device's domain snapshot with the newly reported counts."""
    db.execute(delete(DeviceSiteVisit).where(DeviceSiteVisit.device_id == device_id))
    now = utcnow()
    for s in sites:
        db.add(DeviceSiteVisit(device_id=device_id, domain=s["domain"], visits=int(s["visits"]), updated_at=now))
    db.commit()


def device_top(db: Session, device_id: uuid.UUID, limit: int = 20) -> list[dict]:
    rows = db.execute(
        select(DeviceSiteVisit.domain, DeviceSiteVisit.visits)
        .where(DeviceSiteVisit.device_id == device_id)
        .order_by(DeviceSiteVisit.visits.desc())
        .limit(limit)
    ).all()
    return [{"domain": d, "visits": int(v)} for d, v in rows]


def fleet_top(db: Session, device_ids: list[uuid.UUID], limit: int = 10) -> list[dict]:
    """Top domains across the given (visible) devices, with total visits and how many endpoints visited each."""
    if not device_ids:
        return []
    rows = db.execute(
        select(
            DeviceSiteVisit.domain,
            func.sum(DeviceSiteVisit.visits).label("visits"),
            func.count(func.distinct(DeviceSiteVisit.device_id)).label("endpoints"),
        )
        .where(DeviceSiteVisit.device_id.in_(device_ids))
        .group_by(DeviceSiteVisit.domain)
        .order_by(func.sum(DeviceSiteVisit.visits).desc())
        .limit(limit)
    ).all()
    return [{"domain": d, "visits": int(v), "endpoints": int(e)} for d, v, e in rows]
