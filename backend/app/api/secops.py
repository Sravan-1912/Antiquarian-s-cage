"""Security operations API: alerts and investigation workflow, reports, notification preferences."""
from __future__ import annotations

import re
import uuid
from datetime import date, datetime, time, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, current_context, require_permission
from app.core.database import get_db, utcnow
from app.models import AlertEvent, Device, Organization, SecurityAlert, User
from app.services import alerts, audit, notifications, reports

router = APIRouter(tags=["secops"])
READ = require_permission("alerts:read")
MANAGE = require_permission("alerts:manage")
Status = Literal["new", "triaging", "investigating", "resolved", "false_positive"]
TRANSITIONS = {"new": {"triaging", "investigating", "resolved", "false_positive"},
               "triaging": {"investigating", "resolved", "false_positive"},
               "investigating": {"resolved", "false_positive"},
               "resolved": {"investigating"}, "false_positive": {"investigating"}}


def _out(db: Session, a: SecurityAlert) -> dict:
    d = db.get(Device, a.device_id) if a.device_id else None
    u = db.get(User, a.assigned_to) if a.assigned_to else None
    return {"id": str(a.id), "rule_key": a.rule_key, "rule_name": alerts.RULES.get(a.rule_key, {}).get("name"),
            "kind": a.kind, "title": a.title, "description": a.description, "severity": a.severity,
            "status": a.status, "device_id": str(a.device_id) if a.device_id else None,
            "device_name": d.display_name if d else None,
            "employee_id": str(a.employee_id) if a.employee_id else None, "subject_label": a.subject_label,
            "detected_at": a.detected_at, "last_seen_at": a.last_seen_at, "occurrences": a.occurrences,
            "assigned_to": str(a.assigned_to) if a.assigned_to else None, "assigned_to_label": u.email if u else None,
            "resolution_notes": a.resolution_notes, "resolved_at": a.resolved_at, "evidence": a.evidence,
            "auto_resolvable": a.auto_resolvable}


def _get(db: Session, ctx: AuthContext, aid: uuid.UUID) -> SecurityAlert:
    a = db.get(SecurityAlert, aid)
    if a is None or a.organization_id != ctx.user.organization_id:
        raise HTTPException(404, "Alert not found")
    return a


# ------------------------------------------------------------------------------------------------ alerts
@router.get("/alerts")
def list_alerts(status: Literal["open", "closed", "new", "triaging", "investigating", "resolved", "false_positive"] | None = "open",
                severity: Literal["critical", "high", "medium", "low", "informational"] | None = None,
                kind: Literal["configuration", "operational", "suspicious_activity"] | None = None,
                assigned: Literal["me", "unassigned"] | None = None, device_id: uuid.UUID | None = None,
                q: str | None = Query(None, max_length=100), page: int = Query(1, ge=1),
                page_size: int = Query(50, ge=1, le=200), ctx: AuthContext = Depends(READ),
                db: Session = Depends(get_db)):
    stmt = select(SecurityAlert).where(SecurityAlert.organization_id == ctx.user.organization_id)
    if status == "open":
        stmt = stmt.where(SecurityAlert.status.in_(alerts.OPEN))
    elif status == "closed":
        stmt = stmt.where(SecurityAlert.status.in_(("resolved", "false_positive")))
    elif status:
        stmt = stmt.where(SecurityAlert.status == status)
    if severity:
        stmt = stmt.where(SecurityAlert.severity == severity)
    if kind:
        stmt = stmt.where(SecurityAlert.kind == kind)
    if assigned == "me":
        stmt = stmt.where(SecurityAlert.assigned_to == ctx.user.id)
    elif assigned == "unassigned":
        stmt = stmt.where(SecurityAlert.assigned_to.is_(None))
    if device_id:
        stmt = stmt.where(SecurityAlert.device_id == device_id)
    if q:
        stmt = stmt.where(func.lower(SecurityAlert.title).like(f"%{q.lower()}%"))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(SecurityAlert.last_seen_at.desc()).offset((page - 1) * page_size).limit(page_size))
    return {"items": [_out(db, a) for a in rows], "total": total, "page": page, "page_size": page_size}


@router.get("/alerts/summary")
def alert_summary(ctx: AuthContext = Depends(READ), db: Session = Depends(get_db)):
    org = ctx.user.organization_id
    open_by_sev = dict(db.execute(select(SecurityAlert.severity, func.count()).where(
        SecurityAlert.organization_id == org, SecurityAlert.status.in_(alerts.OPEN)).group_by(SecurityAlert.severity)).all())
    since = utcnow() - timedelta(days=13)
    start = datetime(since.year, since.month, since.day, tzinfo=timezone.utc)
    days = {(start + timedelta(days=i)).date().isoformat(): 0 for i in range(14)}
    for ts in db.scalars(select(SecurityAlert.detected_at).where(SecurityAlert.organization_id == org,
                                                                 SecurityAlert.detected_at >= start)):
        k = ts.date().isoformat()
        if k in days:
            days[k] += 1
    return {"open_by_severity": {s: open_by_sev.get(s, 0) for s in alerts.SEVERITIES},
            "open_total": sum(open_by_sev.values()),
            "unassigned": db.scalar(select(func.count()).select_from(SecurityAlert).where(
                SecurityAlert.organization_id == org, SecurityAlert.status.in_(alerts.OPEN),
                SecurityAlert.assigned_to.is_(None))) or 0,
            "detected_by_day": [{"date": k, "count": v} for k, v in days.items()]}


@router.get("/alerts/analysts")
def analysts(ctx: AuthContext = Depends(READ), db: Session = Depends(get_db)):
    return [{"id": str(u.id), "email": u.email, "full_name": u.full_name}
            for u in notifications.users_with_permission(db, ctx.user.organization_id, "alerts:manage")]


@router.get("/alerts/{aid}")
def get_alert(aid: uuid.UUID, ctx: AuthContext = Depends(READ), db: Session = Depends(get_db)):
    a = _get(db, ctx, aid)
    hist = db.scalars(select(AlertEvent).where(AlertEvent.alert_id == a.id).order_by(AlertEvent.created_at.desc()))
    return {**_out(db, a), "history": [{"kind": h.kind, "actor": h.actor_label, "details": h.details,
                                        "created_at": h.created_at} for h in hist]}


class AlertUpdate(BaseModel):
    status: Status | None = None
    assigned_to: uuid.UUID | None = None
    unassign: bool = False
    note: str | None = Field(default=None, max_length=4000)


@router.patch("/alerts/{aid}")
def update_alert(aid: uuid.UUID, body: AlertUpdate, ctx: AuthContext = Depends(MANAGE), db: Session = Depends(get_db)):
    a = _get(db, ctx, aid)
    changes: dict = {}
    if body.assigned_to or body.unassign:
        if body.assigned_to:
            u = db.get(User, body.assigned_to)
            if u is None or u.organization_id != a.organization_id or "alerts:manage" not in u.permission_keys:
                raise HTTPException(422, "Alerts can only be assigned to analysts with alerts:manage")
        a.assigned_to = None if body.unassign else body.assigned_to
        changes["assigned_to"] = str(a.assigned_to) if a.assigned_to else None
        db.add(AlertEvent(alert_id=a.id, kind="assigned", actor_id=ctx.user.id, actor_label=ctx.user.email,
                          details={"assigned_to": changes["assigned_to"]}))
    if body.status and body.status != a.status:
        if body.status not in TRANSITIONS[a.status]:
            raise HTTPException(409, f"Cannot move an alert from {a.status} to {body.status}")
        if body.status in ("resolved", "false_positive") and not (body.note and len(body.note.strip()) >= 5):
            raise HTTPException(422, "Resolution notes (at least 5 characters) are required to close an alert")
        before = a.status
        a.status = body.status
        if body.status in ("resolved", "false_positive"):
            a.resolved_at, a.resolution_notes = utcnow(), body.note.strip()
        else:
            a.resolved_at = None
        if a.assigned_to is None and body.status in ("triaging", "investigating"):
            a.assigned_to = ctx.user.id  # whoever picks it up owns it
        changes["status"] = {"from": before, "to": body.status}
        db.add(AlertEvent(alert_id=a.id, kind="status", actor_id=ctx.user.id, actor_label=ctx.user.email,
                          details={"from": before, "to": body.status, **({"note": body.note} if body.note else {})}))
    elif body.note:
        db.add(AlertEvent(alert_id=a.id, kind="note", actor_id=ctx.user.id, actor_label=ctx.user.email,
                          details={"note": body.note.strip()}))
        changes["note"] = True
    if not changes:
        raise HTTPException(422, "Nothing to update")
    audit.record(db, a.organization_id, ctx.actor, "alert.updated", target_type="alert", target_id=a.id,
                 target_label=a.title, metadata=changes)
    db.commit()
    return _out(db, a)


# ------------------------------------------------------------------------------------------------ reports
@router.get("/reports")
def report_catalogue(ctx: AuthContext = Depends(require_permission("reports:read")), db: Session = Depends(get_db)):
    return [{"key": r.key, "title": r.title, "description": r.description, "dated": r.dated,
             "available": all(p in ctx.permissions for p in r.permissions) and "reports:export" in ctx.permissions,
             "requires": list(r.permissions)} for r in reports.REPORTS.values()]


@router.get("/reports/{key}")
def export_report(key: str, format: Literal["csv", "pdf"] = "csv", date_from: date | None = None,
                  date_to: date | None = None, ctx: AuthContext = Depends(require_permission("reports:export")),
                  db: Session = Depends(get_db)):
    r = reports.REPORTS.get(key)
    if r is None:
        raise HTTPException(404, "Unknown report")
    missing = [p for p in r.permissions if p not in ctx.permissions]
    if missing:
        audit.record(db, ctx.user.organization_id, ctx.actor, "authz.denied", result="denied",
                     metadata={"required": missing, "report": key})
        db.commit()
        raise HTTPException(403, "You do not have permission to export this report")
    end_d = date_to or utcnow().date()
    start_d = date_from or (end_d - timedelta(days=30))
    if start_d > end_d or (end_d - start_d).days > 366:
        raise HTTPException(422, "Invalid period (max 366 days)")
    start = datetime.combine(start_d, time.min, timezone.utc)
    end = datetime.combine(end_d + timedelta(days=1), time.min, timezone.utc)
    cols, rows = r.build(db, ctx.user.organization_id, start, end)
    org = db.get(Organization, ctx.user.organization_id)
    period = f"{start_d} to {end_d}" if r.dated else None
    stamp = f"{utcnow():%Y%m%d-%H%M}"
    if format == "csv":
        body, media = reports.to_csv(cols, rows), "text/csv; charset=utf-8"
    else:
        body = reports.to_pdf(r, cols, rows, org_name=org.name if org else "", generated_by=ctx.user.email, period=period)
        media = "application/pdf"
    audit.record(db, ctx.user.organization_id, ctx.actor, "report.exported", target_type="report", target_label=key,
                 metadata={"format": format, "rows": len(rows), "period": period})
    db.commit()
    fname = re.sub(r"[^a-z0-9_-]", "", key) + f"-{stamp}.{format}"
    return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{fname}"',
                                                     "Cache-Control": "no-store"})


# ------------------------------------------------------------------------------------------------ preferences
class PrefIn(BaseModel):
    category: str
    in_app: bool
    email: bool
    min_severity: Literal["informational", "low", "medium", "high", "critical"]
    email_min_severity: Literal["informational", "low", "medium", "high", "critical"] = "high"


@router.get("/notifications/preferences")
def get_prefs(ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    return [{"category": c, "label": label, **{k: getattr(notifications.preference(db, ctx.user.id, c), k)
                                               for k in ("in_app", "email", "min_severity",
                                                                      "email_min_severity")}}
            for c, label in notifications.CATEGORIES.items()]


@router.put("/notifications/preferences")
def put_prefs(body: list[PrefIn], ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    from app.models import NotificationPreference

    for p in body:
        if p.category not in notifications.CATEGORIES:
            raise HTTPException(422, f"Unknown category {p.category}")
        row = db.scalar(select(NotificationPreference).where(NotificationPreference.user_id == ctx.user.id,
                                                             NotificationPreference.category == p.category))
        if row is None:
            row = NotificationPreference(user_id=ctx.user.id, category=p.category)
            db.add(row)
        row.in_app, row.email, row.min_severity = p.in_app, p.email, p.min_severity
        row.email_min_severity = p.email_min_severity
    audit.record(db, ctx.user.organization_id, ctx.actor, "notifications.preferences_updated", target_type="user",
                 target_id=ctx.user.id, target_label=ctx.user.email,
                 metadata={p.category: {"in_app": p.in_app, "email": p.email, "min": p.min_severity} for p in body})
    db.commit()
    return get_prefs(ctx, db)
