"""Dynamic endpoint groups + bulk actions (admin console).

Group CRUD is gated on `devices:manage`; bulk actions additionally require the permission their single-device form
needs (`devices:shell` for scripts, `devices:remote`/`devices:isolate` for remote actions, `devices:manage` for status
changes), with a password step-up for sensitive remote actions — exactly as the per-device endpoints enforce.
"""
from __future__ import annotations

import uuid
from typing import Annotated, Union

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, rate_limit, require_permission
from app.core.database import get_db
from app.models import Device, DeviceGroup, Script
from app.schemas import groups as s
from app.schemas import remote as rs
from app.security import passwords
from app.services import audit, devices as devices_svc, groups, remote, scripts, tenancy
from app.services.devices import DeviceError
from app.services.policies import PolicyError

router = APIRouter(tags=["device-groups"])
MANAGE = require_permission("devices:manage")

BulkBody = Annotated[Union[s.BulkScript, s.BulkAction, s.BulkStatus], Field(discriminator="kind")]


def _raise(e: PolicyError):
    raise HTTPException(e.status, e.message)


def _get_group(db: Session, ctx: AuthContext, group_id: uuid.UUID) -> DeviceGroup:
    g = db.get(DeviceGroup, group_id)
    if g is None or g.organization_id != ctx.user.organization_id or not tenancy.can_see(ctx, g.owner_admin_id):
        raise HTTPException(404, "Group not found")
    return g


def _out(db: Session, ctx: AuthContext, g: DeviceGroup) -> s.GroupOut:
    o = s.GroupOut.model_validate(g)
    o.member_count = groups.member_count(db, ctx, g.criteria)
    return o


@router.get("/device-groups", response_model=list[s.GroupOut])
def list_groups(ctx: AuthContext = Depends(MANAGE), db: Session = Depends(get_db)):
    q = tenancy.restrict(select(DeviceGroup).where(DeviceGroup.organization_id == ctx.user.organization_id),
                         DeviceGroup.owner_admin_id, ctx).order_by(DeviceGroup.name)
    return [_out(db, ctx, g) for g in db.scalars(q).all()]


@router.post("/device-groups", response_model=s.GroupOut, status_code=201)
def create_group(body: s.GroupCreate, ctx: AuthContext = Depends(MANAGE), db: Session = Depends(get_db)):
    try:
        g = groups.create_group(db, ctx.user.organization_id, ctx.actor, name=body.name.strip(),
                                description=body.description, criteria=body.criteria.model_dump(exclude_none=True),
                                owner_admin_id=tenancy.owner_for(ctx))
    except PolicyError as e:
        _raise(e)
    return _out(db, ctx, g)


@router.post("/device-groups/preview", response_model=list[s.GroupMemberOut])
def preview_members(body: s.GroupPreviewRequest, ctx: AuthContext = Depends(MANAGE), db: Session = Depends(get_db)):
    """Live preview of which endpoints match a draft set of criteria (capped), for the create/edit form."""
    return [_member_out(d) for d in groups.members(db, ctx, body.criteria.model_dump(exclude_none=True), limit=200)]


@router.get("/device-groups/{group_id}", response_model=s.GroupOut)
def get_group(group_id: uuid.UUID, ctx: AuthContext = Depends(MANAGE), db: Session = Depends(get_db)):
    return _out(db, ctx, _get_group(db, ctx, group_id))


@router.put("/device-groups/{group_id}", response_model=s.GroupOut)
def update_group(group_id: uuid.UUID, body: s.GroupUpdate, ctx: AuthContext = Depends(MANAGE),
                 db: Session = Depends(get_db)):
    g = _get_group(db, ctx, group_id)
    try:
        g = groups.update_group(db, g, ctx.actor, name=body.name.strip(), description=body.description,
                                criteria=body.criteria.model_dump(exclude_none=True))
    except PolicyError as e:
        _raise(e)
    return _out(db, ctx, g)


@router.delete("/device-groups/{group_id}", status_code=204)
def delete_group(group_id: uuid.UUID, ctx: AuthContext = Depends(MANAGE), db: Session = Depends(get_db)):
    groups.delete_group(db, _get_group(db, ctx, group_id), ctx.actor)


def _member_out(d: Device) -> s.GroupMemberOut:
    conn = devices_svc.connectivity(d)
    return s.GroupMemberOut(id=d.id, display_name=d.display_name, hostname=d.hostname, status=d.status,
                            os_name=d.os_name, compliance_state=d.compliance_state, connectivity=conn,
                            online=conn == "online")


@router.get("/device-groups/{group_id}/members", response_model=list[s.GroupMemberOut])
def group_members(group_id: uuid.UUID, ctx: AuthContext = Depends(MANAGE), db: Session = Depends(get_db)):
    g = _get_group(db, ctx, group_id)
    return [_member_out(d) for d in groups.members(db, ctx, g.criteria, limit=500)]


@router.post("/device-groups/{group_id}/bulk", response_model=s.BulkResultOut, status_code=201,
             dependencies=[Depends(rate_limit("group-bulk", 10))])
def bulk(group_id: uuid.UUID, body: BulkBody = Body(...), ctx: AuthContext = Depends(MANAGE),
         db: Session = Depends(get_db)):
    g = _get_group(db, ctx, group_id)
    try:
        targets = groups.resolve_targets(db, ctx, g)
    except PolicyError as e:
        _raise(e)

    results: list[s.BulkResultItem] = []

    # -------- deploy a script to every member ----------------------------------------------------------
    if isinstance(body, s.BulkScript):
        if "devices:shell" not in ctx.permissions:
            raise HTTPException(403, "Deploying a script requires the devices:shell permission")
        sc = db.get(Script, body.script_id)
        if sc is None or sc.organization_id != ctx.user.organization_id or not tenancy.can_see(ctx, sc.owner_admin_id):
            raise HTTPException(404, "Script not found")
        runs = scripts.deploy(db, sc, targets, body.reason.strip(), ctx.actor)
        by_dev = {r.device_id: r for r in runs}
        for d in targets:
            r = by_dev.get(d.id)
            results.append(s.BulkResultItem(device_id=d.id, hostname=d.hostname, ok=r is not None and r.status != "needs_attention",
                                            detail=(r.stderr or None) if r else "not dispatched"))

    # -------- run a remote action on every member ------------------------------------------------------
    elif isinstance(body, s.BulkAction):
        if "devices:remote" not in ctx.permissions:
            raise HTTPException(403, "Remote actions require the devices:remote permission")
        if body.command in ("device.isolate", "device.release") and "devices:isolate" not in ctx.permissions:
            raise HTTPException(403, "Network isolation requires the devices:isolate permission")
        if body.command in rs.SENSITIVE:
            ok = body.step_up is not None and passwords.verify_password(body.step_up.password, ctx.user.password_hash)
            if not ok:
                audit.record(db, ctx.user.organization_id, ctx.actor, "remote.reauth_failed", result="denied",
                             metadata={"action": f"bulk:{body.command}"})
                db.commit()
                raise HTTPException(403, "Password confirmation failed")
        for d in targets:
            try:
                remote.create_action(db, d, body.command, body.parameters, body.reason.strip(), ctx.actor)
                results.append(s.BulkResultItem(device_id=d.id, hostname=d.hostname, ok=True))
            except (PolicyError, DeviceError) as e:
                results.append(s.BulkResultItem(device_id=d.id, hostname=d.hostname, ok=False, detail=e.message))

    # -------- status change on every member ------------------------------------------------------------
    else:  # BulkStatus
        for d in targets:
            try:
                devices_svc.transition(db, d, body.op, body.reason.strip(), ctx.actor)
                results.append(s.BulkResultItem(device_id=d.id, hostname=d.hostname, ok=True))
            except DeviceError as e:
                results.append(s.BulkResultItem(device_id=d.id, hostname=d.hostname, ok=False, detail=e.message))

    dispatched = sum(1 for r in results if r.ok)
    audit.record(db, ctx.user.organization_id, ctx.actor, "device_group.bulk", target_type="device_group",
                 target_id=g.id, target_label=g.name,
                 metadata={"kind": body.kind, "total": len(targets), "dispatched": dispatched})
    db.commit()
    return s.BulkResultOut(kind=body.kind, total=len(targets), dispatched=dispatched,
                           skipped=len(targets) - dispatched, results=results)
