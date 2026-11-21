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
from app.services import alerts, audit, notifications, reports, tenancy

router = APIRouter(tags=["secops"])
READ = require_permission("alerts:read")
MANAGE = require_permission("alerts:manage")
Status = Literal["new", "triaging", "investigating", "resolved", "false_positive"]
TRANSITIONS = {"new": {"triaging", "investigating", "resolved", "false_positive"},
               "triaging": {"investigating", "resolved", "false_positive"},
               "investigating": {"resolved", "false_positive"},
               "resolved": {"investigating"}, "false_positive": {"investigating"}}


def _out(db: Session, a: SecurityAlert, devs: dict | None = None, users: dict | None = None) -> dict:
    d = (devs.get(a.device_id) if devs is not None else db.get(Device, a.device_id)) if a.device_id else None
    u = (users.get(a.assigned_to) if users is not None else db.get(User, a.assigned_to)) if a.assigned_to else None
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
    if a is None or a.organization_id != ctx.user.organization_id or not tenancy.can_see(ctx, a.owner_admin_id):
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
    stmt = tenancy.restrict(select(SecurityAlert).where(SecurityAlert.organization_id == ctx.user.organization_id),
                            SecurityAlert.owner_admin_id, ctx)
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
    rows = db.scalars(stmt.order_by(SecurityAlert.last_seen_at.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    # Referenced devices/users in two queries instead of two per alert.
    dev_ids = {a.device_id for a in rows if a.device_id}
    user_ids = {a.assigned_to for a in rows if a.assigned_to}
    devs = {d.id: d for d in db.scalars(select(Device).where(Device.id.in_(dev_ids)))} if dev_ids else {}
    users = {u.id: u for u in db.scalars(select(User).where(User.id.in_(user_ids)))} if user_ids else {}
    return {"items": [_out(db, a, devs, users) for a in rows], "total": total, "page": page, "page_size": page_size}


@router.get("/alerts/summary")
def alert_summary(ctx: AuthContext = Depends(READ), db: Session = Depends(get_db)):
    org = ctx.user.organization_id
    own = (SecurityAlert.owner_admin_id == tenancy.scope_admin_id(ctx),) if tenancy.scope_admin_id(ctx) is not None else ()
    open_by_sev = dict(db.execute(select(SecurityAlert.severity, func.count()).where(
        SecurityAlert.organization_id == org, SecurityAlert.status.in_(alerts.OPEN), *own).group_by(SecurityAlert.severity)).all())
    since = utcnow() - timedelta(days=13)
    start = datetime(since.year, since.month, since.day, tzinfo=timezone.utc)
    days = {(start + timedelta(days=i)).date().isoformat(): 0 for i in range(14)}
    for ts in db.scalars(select(SecurityAlert.detected_at).where(SecurityAlert.organization_id == org,
                                                                 SecurityAlert.detected_at >= start, *own)):
        k = ts.date().isoformat()
        if k in days:
            days[k] += 1
    return {"open_by_severity": {s: open_by_sev.get(s, 0) for s in alerts.SEVERITIES},
            "open_total": sum(open_by_sev.values()),
            "unassigned": db.scalar(select(func.count()).select_from(SecurityAlert).where(*own, 
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
    cols, rows = r.build(db, ctx.user.organization_id, start, end, tenancy.scope_admin_id(ctx))
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


# --------------------------------------------------------------------------------- SIEM / webhook egress
SIEM_SETTINGS = require_permission("org:settings")


class SiemConfigIn(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    auth_header: str = Field(default="Authorization", max_length=64)
    token: str | None = Field(default=None, max_length=1024)  # write-only; omit to keep the existing token
    enabled: bool = True
    min_severity: Literal["low", "medium", "high", "critical"] = "low"


def _siem_out(dest) -> dict:
    return {"url": dest.url, "auth_header": dest.auth_header, "enabled": dest.enabled,
            "min_severity": dest.min_severity, "has_token": dest.token_enc is not None,
            "last_success_at": dest.last_success_at, "last_error": dest.last_error}


@router.put("/siem")
def put_siem(body: SiemConfigIn, ctx: AuthContext = Depends(SIEM_SETTINGS), db: Session = Depends(get_db)):
    """Configure SIEM / webhook egress: security alerts are POSTed (JSON) to this destination. Token is write-only."""
    from app.core.config import get_settings
    from app.models import SiemDestination
    from app.services import siem
    url = body.url.strip()
    if not url.lower().startswith(("http://", "https://")):
        raise HTTPException(422, "url must be http(s)")
    if get_settings().environment == "production" and not url.lower().startswith("https://"):
        raise HTTPException(422, "SIEM URL must be https in production")
    org = ctx.user.organization_id
    dest = siem.destination(db, org)
    if dest is None:
        dest = SiemDestination(id=uuid.uuid4(), organization_id=org, url=url)
        db.add(dest)
    dest.url, dest.auth_header = url, (body.auth_header or "Authorization")
    dest.enabled, dest.min_severity, dest.updated_at = body.enabled, body.min_severity, utcnow()
    if body.token is not None:
        dest.token_enc = siem.encrypt_token(body.token) if body.token else None
    audit.record(db, org, ctx.actor, "siem.configured", target_type="organization", target_id=org,
                 target_label=None, metadata={"url": url, "enabled": body.enabled, "min_severity": body.min_severity})
    db.commit()
    return _siem_out(dest)


@router.get("/siem")
def get_siem(ctx: AuthContext = Depends(SIEM_SETTINGS), db: Session = Depends(get_db)):
    from app.services import siem
    dest = siem.destination(db, ctx.user.organization_id)
    return _siem_out(dest) if dest else None


@router.post("/siem/test")
def test_siem(ctx: AuthContext = Depends(SIEM_SETTINGS), db: Session = Depends(get_db)):
    """Send a one-off test event to the configured destination and report the result."""
    from app.services import siem
    return siem.send_test(db, ctx.user.organization_id)


# ---- Chat alert channels (Slack / Teams / Discord / generic webhook) ----
class ChatWebhookIn(BaseModel):
    platform: Literal["slack", "teams", "discord", "generic"]
    url: str | None = Field(default=None, max_length=1024)  # write-only; omit to keep the existing URL
    enabled: bool = True
    min_severity: Literal["low", "medium", "high", "critical"] = "high"


def _chat_out(w) -> dict:
    return {"platform": w.platform, "enabled": w.enabled, "min_severity": w.min_severity,
            "configured": w.url_enc is not None, "last_success_at": w.last_success_at, "last_error": w.last_error}


@router.get("/chat-webhooks")
def list_chat_webhooks(ctx: AuthContext = Depends(SIEM_SETTINGS), db: Session = Depends(get_db)):
    from app.services import chat
    return [_chat_out(w) for w in chat.webhooks(db, ctx.user.organization_id)]


@router.put("/chat-webhooks")
def put_chat_webhook(body: ChatWebhookIn, ctx: AuthContext = Depends(SIEM_SETTINGS), db: Session = Depends(get_db)):
    """Configure a chat alert channel. The webhook URL is write-only and stored encrypted."""
    from app.models import ChatWebhook
    from app.services import chat
    org = ctx.user.organization_id
    w = db.scalar(select(ChatWebhook).where(ChatWebhook.organization_id == org, ChatWebhook.platform == body.platform))
    if w is None:
        if not body.url:
            raise HTTPException(422, "url is required for a new channel")
        w = ChatWebhook(id=uuid.uuid4(), organization_id=org, platform=body.platform, url_enc=chat.encrypt_url(body.url.strip()))
        db.add(w)
    elif body.url is not None:
        if not body.url.strip():
            raise HTTPException(422, "url cannot be empty")
        w.url_enc = chat.encrypt_url(body.url.strip())
    w.enabled, w.min_severity = body.enabled, body.min_severity
    audit.record(db, org, ctx.actor, "chat_webhook.configured", target_type="organization", target_id=org,
                 metadata={"platform": body.platform, "enabled": body.enabled, "min_severity": body.min_severity})
    db.commit()
    return _chat_out(w)


@router.delete("/chat-webhooks/{platform}", status_code=204)
def delete_chat_webhook(platform: str, ctx: AuthContext = Depends(SIEM_SETTINGS), db: Session = Depends(get_db)):
    from app.models import ChatWebhook
    w = db.scalar(select(ChatWebhook).where(ChatWebhook.organization_id == ctx.user.organization_id, ChatWebhook.platform == platform))
    if w:
        db.delete(w)
        audit.record(db, ctx.user.organization_id, ctx.actor, "chat_webhook.removed", target_type="organization",
                     target_id=ctx.user.organization_id, metadata={"platform": platform})
        db.commit()


@router.post("/chat-webhooks/{platform}/test")
def test_chat_webhook(platform: str, ctx: AuthContext = Depends(SIEM_SETTINGS), db: Session = Depends(get_db)):
    from app.models import ChatWebhook
    from app.services import chat
    w = db.scalar(select(ChatWebhook).where(ChatWebhook.organization_id == ctx.user.organization_id, ChatWebhook.platform == platform))
    if w is None:
        raise HTTPException(404, "channel not configured")
    return chat.send_test(db, w)


# ---- Automated-response playbooks (SOAR) ----
class PlaybookIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    enabled: bool = True
    match_rule_keys: list[str] = Field(default_factory=list, max_length=40)
    match_min_severity: Literal["critical", "high", "medium", "low", "informational"] = "high"
    match_kinds: list[Literal["configuration", "operational", "suspicious_activity"]] = Field(default_factory=list, max_length=5)
    actions: list[Literal["isolate", "escalate", "comment"]] = Field(default_factory=list, max_length=5)


def _pb_out(pb) -> dict:
    return {"id": str(pb.id), "name": pb.name, "enabled": pb.enabled, "match_rule_keys": pb.match_rule_keys,
            "match_min_severity": pb.match_min_severity, "match_kinds": pb.match_kinds, "actions": pb.actions}


@router.get("/playbooks")
def list_playbooks(ctx: AuthContext = Depends(SIEM_SETTINGS), db: Session = Depends(get_db)):
    from app.models import ResponsePlaybook
    rows = db.scalars(select(ResponsePlaybook).where(ResponsePlaybook.organization_id == ctx.user.organization_id)
                      .order_by(ResponsePlaybook.created_at)).all()
    return [_pb_out(p) for p in rows]


@router.get("/playbooks/rule-keys")
def playbook_rule_keys(_: AuthContext = Depends(SIEM_SETTINGS)):
    """The alert rules a playbook can trigger on (key + human name), for the config UI."""
    from app.services.alerts import RULES
    return [{"key": k, "name": v["name"], "kind": v["kind"]} for k, v in RULES.items()]


@router.post("/playbooks", status_code=201)
def create_playbook(body: PlaybookIn, ctx: AuthContext = Depends(SIEM_SETTINGS), db: Session = Depends(get_db)):
    from app.models import ResponsePlaybook
    pb = ResponsePlaybook(id=uuid.uuid4(), organization_id=ctx.user.organization_id, name=body.name, enabled=body.enabled,
                          match_rule_keys=body.match_rule_keys, match_min_severity=body.match_min_severity,
                          match_kinds=body.match_kinds, actions=body.actions)
    db.add(pb)
    audit.record(db, ctx.user.organization_id, ctx.actor, "playbook.created", target_type="playbook", target_id=pb.id,
                 target_label=body.name, metadata={"actions": body.actions, "min_severity": body.match_min_severity})
    db.commit()
    return _pb_out(pb)


@router.put("/playbooks/{pid}")
def update_playbook(pid: uuid.UUID, body: PlaybookIn, ctx: AuthContext = Depends(SIEM_SETTINGS), db: Session = Depends(get_db)):
    from app.models import ResponsePlaybook
    pb = db.scalar(select(ResponsePlaybook).where(ResponsePlaybook.id == pid, ResponsePlaybook.organization_id == ctx.user.organization_id))
    if pb is None:
        raise HTTPException(404, "playbook not found")
    pb.name, pb.enabled = body.name, body.enabled
    pb.match_rule_keys, pb.match_min_severity, pb.match_kinds, pb.actions = body.match_rule_keys, body.match_min_severity, body.match_kinds, body.actions
    pb.updated_at = utcnow()
    audit.record(db, ctx.user.organization_id, ctx.actor, "playbook.updated", target_type="playbook", target_id=pb.id, target_label=body.name)
    db.commit()
    return _pb_out(pb)


@router.delete("/playbooks/{pid}", status_code=204)
def delete_playbook(pid: uuid.UUID, ctx: AuthContext = Depends(SIEM_SETTINGS), db: Session = Depends(get_db)):
    from app.models import ResponsePlaybook
    pb = db.scalar(select(ResponsePlaybook).where(ResponsePlaybook.id == pid, ResponsePlaybook.organization_id == ctx.user.organization_id))
    if pb:
        db.delete(pb)
        audit.record(db, ctx.user.organization_id, ctx.actor, "playbook.removed", target_type="playbook", target_id=pid, target_label=pb.name)
        db.commit()
