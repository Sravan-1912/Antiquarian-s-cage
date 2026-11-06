"""Endpoint administration (admin console)."""
from __future__ import annotations

import csv
import io
import uuid
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, require_permission
from app.core.config import get_settings
from app.core.database import get_db, utcnow
from app.models import (
    Device, DeviceCertificate, DeviceEvent, DeviceHeartbeat, DeviceInventory, Employee, EnrollmentToken, User,
)
from app.schemas import endpoints as s
from app.schemas.common import Page
from app.services import audit, devices
from app.services.devices import DeviceError

router = APIRouter(tags=["endpoints"])
READ = require_permission("devices:read", "devices:read_assigned", any_of=True)


def _scope(stmt, ctx: AuthContext):
    stmt = stmt.where(Device.organization_id == ctx.user.organization_id)
    if "devices:read" not in ctx.permissions:  # IT support: only endpoints assigned to them
        stmt = stmt.where(Device.support_owner_id == ctx.user.id)
    return stmt


def _get(db: Session, ctx: AuthContext, device_id: uuid.UUID) -> Device:
    d = db.scalar(_scope(select(Device).where(Device.id == device_id), ctx))
    if d is None:
        raise HTTPException(404, "Endpoint not found")
    return d


def _out(db: Session, d: Device) -> s.DeviceOut:
    o = s.DeviceOut.model_validate(d)
    o.connectivity = devices.connectivity(d)
    o.online = o.connectivity == "online"
    if d.employee_id:
        emp = db.get(Employee, d.employee_id)
        o.employee_name = emp.full_name if emp else None
    return o


def _raise(e: DeviceError):
    raise HTTPException(e.status, e.message)


# ------------------------------------------------------------------------------------------- enrollment tokens
@router.get("/enrollment-tokens", response_model=list[s.EnrollmentTokenOut])
def list_tokens(ctx: AuthContext = Depends(require_permission("devices:manage")), db: Session = Depends(get_db)):
    rows = db.scalars(select(EnrollmentToken).where(EnrollmentToken.organization_id == ctx.user.organization_id)
                      .order_by(EnrollmentToken.created_at.desc()).limit(100)).all()
    out = []
    for t in rows:
        o = s.EnrollmentTokenOut.model_validate(t)
        o.state = devices.token_state(t)
        out.append(o)
    return out


@router.post("/enrollment-tokens", response_model=s.EnrollmentTokenCreated, status_code=201)
def create_token(body: s.EnrollmentTokenCreate, ctx: AuthContext = Depends(require_permission("devices:manage")),
                 db: Session = Depends(get_db)):
    if body.employee_id:
        emp = db.get(Employee, body.employee_id)
        if emp is None or emp.organization_id != ctx.user.organization_id:
            raise HTTPException(404, "Employee not found")
        if emp.status in ("suspended", "offboarded"):
            raise HTTPException(409, f"Cannot enrol a device for a {emp.status} employee")
    tok, raw = devices.create_enrollment_token(db, ctx.user.organization_id, ctx.actor, label=body.label,
                                               employee_id=body.employee_id, minutes=body.expires_in_minutes)
    db.commit()
    return s.EnrollmentTokenCreated(**s.EnrollmentTokenOut.model_validate(tok).model_dump(), token=raw)


@router.post("/enrollment-tokens/{token_id}/revoke", response_model=s.EnrollmentTokenOut)
def revoke_token(token_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("devices:manage")),
                 db: Session = Depends(get_db)):
    t = db.get(EnrollmentToken, token_id)
    if t is None or t.organization_id != ctx.user.organization_id:
        raise HTTPException(404, "Token not found")
    if devices.token_state(t) != "active":
        raise HTTPException(409, "Only active tokens can be revoked")
    t.revoked_at = utcnow()
    audit.record(db, t.organization_id, ctx.actor, "device.enrollment_token_revoked", target_type="enrollment_token",
                 target_id=t.id, target_label=t.label)
    db.commit()
    o = s.EnrollmentTokenOut.model_validate(t)
    o.state = "revoked"
    return o


# ------------------------------------------------------------------------------------------- devices
def _filtered(ctx: AuthContext, q: str | None, status: str | None, connectivity: str | None,
              employee_id: uuid.UUID | None):
    stmt = _scope(select(Device), ctx)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(Device.hostname).like(like), func.lower(Device.display_name).like(like),
                              func.lower(Device.serial_number).like(like), func.lower(Device.model).like(like)))
    if status:
        stmt = stmt.where(Device.status == status)
    if employee_id:
        stmt = stmt.where(Device.employee_id == employee_id)
    if connectivity:
        cutoff = utcnow() - timedelta(seconds=get_settings().offline_threshold_seconds)
        stmt = stmt.where({"online": Device.last_heartbeat_at >= cutoff,
                           "offline": Device.last_heartbeat_at < cutoff,
                           "never": Device.last_heartbeat_at.is_(None)}[connectivity])
    return stmt


@router.get("/devices", response_model=Page[s.DeviceOut])
def list_devices(
    q: str | None = Query(None, max_length=100),
    status: Literal["active", "suspended", "revoked", "unenrolled"] | None = None,
    connectivity: Literal["online", "offline", "never"] | None = None,
    employee_id: uuid.UUID | None = None,
    page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100),
    ctx: AuthContext = Depends(READ), db: Session = Depends(get_db),
):
    stmt = _filtered(ctx, q, status, connectivity, employee_id)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(Device.hostname, Device.id).offset((page - 1) * page_size).limit(page_size)).all()
    return Page(items=[_out(db, d) for d in rows], total=total, page=page, page_size=page_size)


@router.get("/devices/export.csv")
def export_devices(
    q: str | None = Query(None, max_length=100),
    status: Literal["active", "suspended", "revoked", "unenrolled"] | None = None,
    connectivity: Literal["online", "offline", "never"] | None = None,
    ctx: AuthContext = Depends(require_permission("devices:read", "reports:export")), db: Session = Depends(get_db),
):
    rows = db.scalars(_filtered(ctx, q, status, connectivity, None).order_by(Device.hostname)).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["device_id", "hostname", "status", "connectivity", "employee", "os", "os_version", "manufacturer",
                "model", "serial", "agent_version", "enrolled_at", "last_heartbeat_at", "last_seen_ip"])
    for d in rows:
        o = _out(db, d)
        w.writerow([_safe(v) for v in (d.id, d.hostname, d.status, o.connectivity, o.employee_name or "", d.os_name,
                                       d.os_version, d.manufacturer, d.model, d.serial_number, d.agent_version,
                                       d.enrolled_at.isoformat(), d.last_heartbeat_at.isoformat()
                                       if d.last_heartbeat_at else "", d.last_seen_ip)])
    audit.record(db, ctx.user.organization_id, ctx.actor, "report.exported", target_type="report",
                 target_label="endpoints.csv", metadata={"rows": len(rows)})
    db.commit()
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="endpoints.csv"'})


def _safe(v: object) -> str:
    t = "" if v is None else str(v)
    return "'" + t if t[:1] in ("=", "+", "-", "@", "\t", "\r") else t


@router.get("/devices/{device_id}", response_model=s.DeviceOut)
def get_device(device_id: uuid.UUID, ctx: AuthContext = Depends(READ), db: Session = Depends(get_db)):
    return _out(db, _get(db, ctx, device_id))


@router.get("/devices/{device_id}/inventory", response_model=s.InventoryOut | None)
def latest_inventory(device_id: uuid.UUID, ctx: AuthContext = Depends(READ), db: Session = Depends(get_db)):
    _get(db, ctx, device_id)
    return db.scalar(select(DeviceInventory).where(DeviceInventory.device_id == device_id)
                     .order_by(DeviceInventory.collected_at.desc()).limit(1))


@router.get("/devices/{device_id}/events", response_model=list[s.DeviceEventOut])
def device_events(device_id: uuid.UUID, ctx: AuthContext = Depends(READ), db: Session = Depends(get_db)):
    _get(db, ctx, device_id)
    return db.scalars(select(DeviceEvent).where(DeviceEvent.device_id == device_id)
                      .order_by(DeviceEvent.created_at.desc()).limit(200)).all()


@router.get("/devices/{device_id}/heartbeats", response_model=list[s.HeartbeatOut])
def device_heartbeats(device_id: uuid.UUID, ctx: AuthContext = Depends(READ), db: Session = Depends(get_db)):
    _get(db, ctx, device_id)
    return db.scalars(select(DeviceHeartbeat).where(DeviceHeartbeat.device_id == device_id)
                      .order_by(DeviceHeartbeat.received_at.desc()).limit(100)).all()


@router.get("/devices/{device_id}/certificates", response_model=list[s.CertificateOut])
def device_certificates(device_id: uuid.UUID, ctx: AuthContext = Depends(READ), db: Session = Depends(get_db)):
    _get(db, ctx, device_id)
    return db.scalars(select(DeviceCertificate).where(DeviceCertificate.device_id == device_id)
                      .order_by(DeviceCertificate.created_at.desc())).all()


@router.patch("/devices/{device_id}", response_model=s.DeviceOut)
def update_device(device_id: uuid.UUID, body: s.DeviceUpdate,
                  ctx: AuthContext = Depends(require_permission("devices:manage")), db: Session = Depends(get_db)):
    d = _get(db, ctx, device_id)
    changes = body.model_dump(exclude_unset=True)
    if changes.get("employee_id"):
        emp = db.get(Employee, changes["employee_id"])
        if emp is None or emp.organization_id != d.organization_id:
            raise HTTPException(404, "Employee not found")
        if emp.status == "offboarded":
            raise HTTPException(409, "Cannot assign an endpoint to an offboarded employee")
    if changes.get("support_owner_id"):
        u = db.get(User, changes["support_owner_id"])
        if u is None or u.organization_id != d.organization_id or u.status != "active":
            raise HTTPException(404, "Administrator not found")
    return _out(db, devices.assign(db, d, changes, ctx.actor))


@router.post("/devices/{device_id}/{op}", response_model=s.DeviceOut)
def device_action(device_id: uuid.UUID, op: Literal["suspend", "reactivate", "revoke", "unenroll"],
                  body: s.DeviceActionRequest, ctx: AuthContext = Depends(require_permission("devices:manage")),
                  db: Session = Depends(get_db)):
    d = _get(db, ctx, device_id)
    try:
        return _out(db, devices.transition(db, d, op, body.reason, ctx.actor))
    except DeviceError as e:
        _raise(e)
