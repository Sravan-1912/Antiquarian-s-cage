"""Dashboard, audit log, notifications and global search."""
from __future__ import annotations

import csv
import io
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, current_context, require_permission
from app.core.database import get_db, utcnow
from app.core.config import get_settings
from app.models import AuditLog, AuthenticationEvent, Device, Employee, Notification, User, UserSession
from app.schemas.admin import AnchorReportOut, AuditAnchorOut, AuditOut, AuditVerifyOut, NotificationOut, SearchHit
from app.schemas.common import Message, Page
from app.services import audit, audit_anchor, tenancy
from app.services import devices as devices_svc
from fastapi.responses import PlainTextResponse
from app.models import AuditAnchor

router = APIRouter(tags=["operations"])


# ------------------------------------------------------------------------------------------- dashboard
@router.get("/dashboard/summary")
def dashboard_summary(ctx: AuthContext = Depends(require_permission("dashboard:read")),
                      db: Session = Depends(get_db)):
    """All values are computed from the database. Endpoint, policy and alert sections report
    `available: false` until their modules are deployed, rather than fabricating numbers."""
    org = ctx.user.organization_id
    now = utcnow()
    since = now - timedelta(days=13)
    scope = tenancy.scope_admin_id(ctx)  # admin isolation: None for Super Admin (global)
    emp_f = (Employee.owner_admin_id == scope,) if scope is not None else ()
    usr_f = (or_(User.owner_admin_id == scope, User.id == scope),) if scope is not None else ()
    tenant_uids = None
    if scope is not None:
        tenant_uids = list(db.scalars(select(User.id).where(User.organization_id == org, *usr_f)))
    auth_f = (AuthenticationEvent.user_id.in_(tenant_uids),) if tenant_uids is not None else ()
    start_day = datetime(since.year, since.month, since.day, tzinfo=timezone.utc)

    by_status = dict(db.execute(select(Employee.status, func.count()).where(Employee.organization_id == org, *emp_f)
                                .group_by(Employee.status)).all())
    by_dept = db.execute(select(Employee.department, func.count()).where(Employee.organization_id == org,
                                                                        Employee.status != "offboarded", *emp_f)
                         .group_by(Employee.department).order_by(func.count().desc()).limit(8)).all()

    events = db.execute(select(AuthenticationEvent.created_at, AuthenticationEvent.success)
                        .where(AuthenticationEvent.organization_id == org,
                               AuthenticationEvent.event_type == "login",
                               AuthenticationEvent.created_at >= start_day, *auth_f)).all()
    days = {(start_day + timedelta(days=i)).date().isoformat(): {"success": 0, "failure": 0} for i in range(14)}
    for ts, ok in events:
        key = ts.date().isoformat()
        if key in days:
            days[key]["success" if ok else "failure"] += 1

    joiners = db.execute(select(Employee.created_at).where(Employee.organization_id == org,
                                                           Employee.created_at >= start_day, *emp_f)).scalars().all()
    join_days = {k: 0 for k in days}
    for ts in joiners:
        k = ts.date().isoformat()
        if k in join_days:
            join_days[k] += 1

    failed_24h = db.scalar(select(func.count()).select_from(AuthenticationEvent).where(
        AuthenticationEvent.organization_id == org, AuthenticationEvent.event_type == "login",
        AuthenticationEvent.success.is_(False), AuthenticationEvent.created_at >= now - timedelta(hours=24), *auth_f)) or 0
    locked = db.scalar(select(func.count()).select_from(User).where(User.organization_id == org,
                                                                   User.locked_until > now, *usr_f)) or 0
    admins = db.execute(select(User.status, User.mfa_enabled).where(User.organization_id == org, *usr_f)).all()

    recent = []
    if "audit:read" in ctx.permissions:
        recent = [
            {"id": str(a.id), "action": a.action, "actor": a.actor_label, "target": a.target_label,
             "result": a.result, "created_at": a.created_at.isoformat()}
            for a in db.scalars(select(AuditLog).where(AuditLog.organization_id == org)
                                .order_by(AuditLog.seq.desc()).limit(10))
        ]

    return {
        "generated_at": now.isoformat(),
        "employees": {
            "active": by_status.get("active", 0),
            "invited": by_status.get("invited", 0),
            "suspended": by_status.get("suspended", 0),
            "offboarded": by_status.get("offboarded", 0),
            "by_department": [{"department": d, "count": c} for d, c in by_dept],
            "joiners_by_day": [{"date": k, "count": v} for k, v in join_days.items()],
        },
        "authentication": {
            "failed_logins_24h": failed_24h,
            "locked_accounts": locked,
            "logins_by_day": [{"date": k, **v} for k, v in days.items()],
        },
        "administrators": {
            "total": len(admins),
            "active": sum(1 for s, _ in admins if s == "active"),
            "mfa_enabled": sum(1 for s, m in admins if s == "active" and m),
            # "Online" = a live session used in the last 15 minutes (real activity, not a guess).
            "online": db.scalar(select(func.count(func.distinct(UserSession.user_id))).join(User, User.id == UserSession.user_id)
                                .where(User.organization_id == org, UserSession.revoked_at.is_(None),
                                       UserSession.expires_at > now,
                                       UserSession.last_seen_at >= now - timedelta(minutes=15), *usr_f)) or 0,
        },
        "endpoints": _endpoint_summary(db, ctx, start_day, now) if (
            "devices:read" in ctx.permissions) else {"available": False, "module": "Endpoint management",
                                                     "phase": 2, "restricted": True},
        "compliance": _compliance_summary(db, ctx) if "compliance:read" in ctx.permissions else {
            "available": False, "module": "Compliance engine", "phase": 3, "restricted": True},
        "policies": _policy_summary(db, ctx) if "policies:read" in ctx.permissions else {
            "available": False, "module": "Policy engine", "phase": 3, "restricted": True},
        "alerts": _alerts_summary(db, ctx) if "alerts:read" in ctx.permissions else {
            "available": False, "module": "Security alerts", "phase": 6, "restricted": True},
        "recent_activity": recent,
        "recent_activity_visible": "audit:read" in ctx.permissions,
    }


def _endpoint_summary(db: Session, ctx: AuthContext, start_day: datetime, now: datetime) -> dict:
    org = ctx.user.organization_id
    scope = tenancy.scope_admin_id(ctx)
    own = (Device.owner_admin_id == scope,) if scope is not None else ()
    cutoff = now - timedelta(seconds=get_settings().offline_threshold_seconds)
    managed = (Device.organization_id == org, Device.status.in_(("active", "suspended")), *own)
    by_status = dict(db.execute(select(Device.status, func.count()).where(Device.organization_id == org, *own)
                                .group_by(Device.status)).all())
    online = db.scalar(select(func.count()).select_from(Device).where(*managed, Device.last_heartbeat_at >= cutoff)) or 0
    never = db.scalar(select(func.count()).select_from(Device).where(*managed, Device.last_heartbeat_at.is_(None))) or 0
    total = by_status.get("active", 0) + by_status.get("suspended", 0)
    os_rows = db.execute(select(Device.os_name, func.count()).where(*managed).group_by(Device.os_name)
                         .order_by(func.count().desc())).all()
    enrolled = db.scalars(select(Device.enrolled_at).where(Device.organization_id == org,
                                                           Device.enrolled_at >= start_day, *own)).all()
    per_day = {(start_day + timedelta(days=i)).date().isoformat(): 0 for i in range(14)}
    for ts in enrolled:
        k = ts.date().isoformat()
        if k in per_day:
            per_day[k] += 1
    compliance = dict(db.execute(select(Device.compliance_state, func.count()).where(*managed)
                                 .group_by(Device.compliance_state)).all())
    seen = db.scalars(select(Device.last_heartbeat_at).where(*managed)).all()
    buckets = {"online": 0, "under_1h": 0, "1h_24h": 0, "1d_7d": 0, "over_7d": 0, "never": 0}
    for ts in seen:
        if ts is None:
            buckets["never"] += 1
        elif ts >= cutoff:
            buckets["online"] += 1
        elif ts >= now - timedelta(hours=1):
            buckets["under_1h"] += 1
        elif ts >= now - timedelta(hours=24):
            buckets["1h_24h"] += 1
        elif ts >= now - timedelta(days=7):
            buckets["1d_7d"] += 1
        else:
            buckets["over_7d"] += 1
    platforms: dict[str, int] = {}
    for o, c in os_rows:
        fam = "Windows" if o and "windows" in o.lower() else ("macOS" if o and "mac" in o.lower() else
                                                              ("Linux" if o and "linux" in o.lower() else "Unknown"))
        platforms[fam] = platforms.get(fam, 0) + c
    net = devices_svc.network_usage(db, org, 24, owner_admin_id=scope)
    net.pop("per_device", None)
    return {
        "available": True,
        "enrolled": total,
        "online": online,
        "offline": total - online - never,
        "never_reported": never,
        "suspended": by_status.get("suspended", 0),
        "revoked": by_status.get("revoked", 0),
        "unenrolled": by_status.get("unenrolled", 0),
        "os_distribution": [{"os": o or "Unknown (no inventory yet)", "count": c} for o, c in os_rows],
        "enrollments_by_day": [{"date": k, "count": v} for k, v in per_day.items()],
        "compliance_states": compliance,
        "offline_threshold_seconds": get_settings().offline_threshold_seconds,
        "last_contact": buckets,
        "platforms": [{"platform": k, "count": v} for k, v in sorted(platforms.items(), key=lambda x: -x[1])],
        "network": net,
    }


def _alerts_summary(db: Session, ctx: AuthContext) -> dict:
    from app.api.secops import alert_summary
    return {"available": True, **alert_summary(ctx, db)}


def _compliance_summary(db: Session, ctx: AuthContext) -> dict:
    from app.services import compliance
    org = ctx.user.organization_id
    scope = tenancy.scope_admin_id(ctx)
    own = (Device.owner_admin_id == scope,) if scope is not None else ()
    managed = (Device.organization_id == org, Device.status.in_(("active", "suspended")), *own)
    states = dict(db.execute(select(Device.compliance_state, func.count()).where(*managed)
                             .group_by(Device.compliance_state)).all())
    hist = compliance.org_history(db, org, 14, owner_admin_id=scope)
    return {"available": True, "compliant": states.get("compliant", 0), "non_compliant": states.get("non_compliant", 0),
            "unknown": states.get("unknown", 0),
            "trend": [{"date": h["date"], "average_score": h["average_score"], "non_compliant": h["non_compliant"]}
                      for h in hist]}


def _policy_summary(db: Session, ctx: AuthContext) -> dict:
    from app.models import EndpointPolicy, PolicyDeployment
    org = ctx.user.organization_id
    scope = tenancy.scope_admin_id(ctx)
    own = (EndpointPolicy.owner_admin_id == scope,) if scope is not None else ()
    rows = dict(db.execute(select(PolicyDeployment.status, func.count())
                           .join(EndpointPolicy, EndpointPolicy.id == PolicyDeployment.policy_id)
                           .where(EndpointPolicy.organization_id == org,
                                  PolicyDeployment.created_at >= utcnow() - timedelta(days=30), *own)
                           .group_by(PolicyDeployment.status)).all())
    finished = rows.get("applied", 0) + rows.get("failed", 0) + rows.get("needs_attention", 0)
    by_pstatus = dict(db.execute(select(EndpointPolicy.status, func.count()).where(EndpointPolicy.organization_id == org, *own)
                                 .group_by(EndpointPolicy.status)).all())
    return {"available": True, "active_policies": by_pstatus.get("active", 0),
            "total_policies": sum(by_pstatus.values()), "inactive_policies": sum(by_pstatus.values()) - by_pstatus.get("active", 0),
            "pending": rows.get("pending", 0) + rows.get("in_progress", 0) + rows.get("offline", 0),
            "by_status": rows,
            "success_rate": round(100 * rows.get("applied", 0) / finished) if finished else None}


# ------------------------------------------------------------------------------------------- audit
def _audit_query(ctx: AuthContext, action: str | None, actor: str | None, result: str | None,
                 date_from: date | None, date_to: date | None):
    stmt = select(AuditLog).where(AuditLog.organization_id == ctx.user.organization_id)
    if action:
        stmt = stmt.where(AuditLog.action.like(f"{action}%"))
    if actor:
        stmt = stmt.where(func.lower(AuditLog.actor_label).like(f"%{actor.lower()}%"))
    if result:
        stmt = stmt.where(AuditLog.result == result)
    if date_from:
        stmt = stmt.where(AuditLog.created_at >= datetime.combine(date_from, datetime.min.time(), timezone.utc))
    if date_to:
        stmt = stmt.where(AuditLog.created_at < datetime.combine(date_to + timedelta(days=1), datetime.min.time(),
                                                                 timezone.utc))
    return stmt


@router.get("/audit", response_model=Page[AuditOut])
def list_audit(
    action: str | None = Query(None, max_length=64),
    actor: str | None = Query(None, max_length=100),
    result: Literal["success", "failure", "denied"] | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    ctx: AuthContext = Depends(require_permission("audit:read")),
    db: Session = Depends(get_db),
):
    stmt = _audit_query(ctx, action, actor, result, date_from, date_to)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(AuditLog.seq.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    return Page(items=[AuditOut.model_validate(r) for r in rows], total=total, page=page, page_size=page_size)


@router.get("/audit/actions", response_model=list[str])
def audit_actions(ctx: AuthContext = Depends(require_permission("audit:read")), db: Session = Depends(get_db)):
    return db.scalars(select(AuditLog.action).where(AuditLog.organization_id == ctx.user.organization_id)
                      .distinct().order_by(AuditLog.action)).all()


@router.post("/audit/verify", response_model=AuditVerifyOut)
def verify_audit(ctx: AuthContext = Depends(require_permission("audit:verify")), db: Session = Depends(get_db)):
    org = ctx.user.organization_id
    res = audit.verify_chain(db, org)
    anchors = audit_anchor.verify_anchors(db, org)
    ok = res.valid and anchors.valid
    audit.record(db, org, ctx.actor, "audit.verified", result="success" if ok else "failure",
                 metadata={"checked": res.checked, "valid": res.valid, "first_invalid_seq": res.first_invalid_seq,
                           "anchors_checked": anchors.anchors_checked, "anchor_problems": anchors.problems[:10]})
    db.commit()
    out = AuditVerifyOut(**res.__dict__, anchors=AnchorReportOut(**anchors.__dict__))
    if not anchors.valid:
        out.valid = False
        out.reason = out.reason or anchors.problems[0]
    return out


@router.get("/audit/anchors", response_model=list[AuditAnchorOut])
def list_anchors(ctx: AuthContext = Depends(require_permission("audit:verify")), db: Session = Depends(get_db)):
    return db.scalars(select(AuditAnchor).where(AuditAnchor.organization_id == ctx.user.organization_id)
                      .order_by(AuditAnchor.seq.desc()).limit(50)).all()


@router.post("/audit/anchors", response_model=AuditAnchorOut | None)
def create_anchor(ctx: AuthContext = Depends(require_permission("audit:verify")), db: Session = Depends(get_db)):
    """Anchor the current head now (e.g. before maintenance or a backup)."""
    org = ctx.user.organization_id
    problem = audit_anchor.check_latest(db, org)
    if problem:
        raise HTTPException(409, f"Refusing to anchor: {problem}")
    audit.record(db, org, ctx.actor, "audit.anchor_requested")
    a = audit_anchor.create_anchor(db, org, force=True)
    db.commit()
    return a


@router.get("/audit/anchors/public-key", response_class=PlainTextResponse)
def anchor_public_key(ctx: AuthContext = Depends(require_permission("audit:verify"))):
    return audit_anchor.public_key_pem()


@router.get("/audit/export.csv")
def export_audit(
    action: str | None = Query(None, max_length=64),
    actor: str | None = Query(None, max_length=100),
    result: Literal["success", "failure", "denied"] | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    ctx: AuthContext = Depends(require_permission("audit:read", "reports:export")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(_audit_query(ctx, action, actor, result, date_from, date_to).order_by(AuditLog.seq)
                      .limit(50000)).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["seq", "timestamp", "actor", "action", "target_type", "target", "source_ip", "result", "hash",
                "prev_hash"])
    for r in rows:
        w.writerow([r.seq, r.created_at.isoformat(), r.actor_label, r.action, r.target_type or "",
                    r.target_label or "", r.source_ip or "", r.result, r.hash, r.prev_hash])
    audit.record(db, ctx.user.organization_id, ctx.actor, "report.exported", target_type="report",
                 target_label="audit.csv", metadata={"rows": len(rows)})
    db.commit()
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="audit-log.csv"'})


# ------------------------------------------------------------------------------------------- notifications
@router.get("/notifications", response_model=list[NotificationOut])
def list_notifications(unread_only: bool = False, ctx: AuthContext = Depends(current_context),
                       db: Session = Depends(get_db)):
    stmt = select(Notification).where(Notification.user_id == ctx.user.id)
    if unread_only:
        stmt = stmt.where(Notification.read_at.is_(None))
    return db.scalars(stmt.order_by(Notification.created_at.desc()).limit(100)).all()


@router.get("/notifications/unread-count")
def unread_count(ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    n = db.scalar(select(func.count()).select_from(Notification).where(Notification.user_id == ctx.user.id,
                                                                      Notification.read_at.is_(None))) or 0
    return {"count": n}


@router.post("/notifications/{nid}/read", response_model=Message)
def mark_read(nid: uuid.UUID, ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    n = db.get(Notification, nid)
    if n is None or n.user_id != ctx.user.id:
        raise HTTPException(404, "Notification not found")
    n.read_at = n.read_at or utcnow()
    db.commit()
    return Message(detail="ok")


@router.post("/notifications/read-all", response_model=Message)
def mark_all_read(ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    db.execute(update(Notification).where(Notification.user_id == ctx.user.id, Notification.read_at.is_(None))
               .values(read_at=utcnow()))
    db.commit()
    return Message(detail="ok")


# ------------------------------------------------------------------------------------------- search
@router.get("/search", response_model=list[SearchHit])
def search(q: str = Query(min_length=2, max_length=100), ctx: AuthContext = Depends(current_context),
           db: Session = Depends(get_db)):
    """Results are filtered by the caller's permissions server-side."""
    like = f"%{q.lower()}%"
    org = ctx.user.organization_id
    hits: list[SearchHit] = []
    if "devices:read" in ctx.permissions:
        for d in db.scalars(select(Device).where(
                Device.organization_id == org,
                or_(func.lower(Device.hostname).like(like), func.lower(Device.serial_number).like(like))).limit(5)):
            hits.append(SearchHit(type="endpoint", id=str(d.id), title=d.hostname,
                                  subtitle=f"{d.os_name or 'OS unknown'} · {d.status}", link=f"/endpoints/{d.id}"))
    if "employees:read" in ctx.permissions:
        for e in db.scalars(select(Employee).where(
                Employee.organization_id == org,
                or_(func.lower(Employee.full_name).like(like), func.lower(Employee.email).like(like),
                    func.lower(Employee.employee_number).like(like))).limit(8)):
            hits.append(SearchHit(type="employee", id=str(e.id), title=e.full_name,
                                  subtitle=f"{e.employee_number} · {e.department} · {e.status}",
                                  link=f"/employees/{e.id}"))
    if "users:read" in ctx.permissions:
        for u in db.scalars(select(User).where(User.organization_id == org, or_(
                func.lower(User.full_name).like(like), func.lower(User.email).like(like))).limit(5)):
            hits.append(SearchHit(type="administrator", id=str(u.id), title=u.full_name,
                                  subtitle=f"{u.email} · {', '.join(r.name for r in u.roles)}", link="/administrators"))
    return hits
