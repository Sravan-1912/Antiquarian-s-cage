"""Scripts library + deployment API (admin console).

Gated on `devices:shell` — the same permission class as the break-glass live-response shell, since deploying a script
runs operator-authored code on endpoints. Admin isolation applies to the library (`owner_admin_id`) and to deploy
targets (device scope). Every create/update/delete/deploy is audited; per-endpoint results are captured as ScriptRuns.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, rate_limit, require_permission
from app.api.devices import _get as get_device
from app.core.database import get_db
from app.models import Script
from app.schemas import scripts as s
from app.services import scripts, tenancy
from app.services.policies import PolicyError

router = APIRouter(tags=["scripts"])
SHELL = require_permission("devices:shell")


def _raise(e: PolicyError):
    raise HTTPException(e.status, e.message)


def _get_script(db: Session, ctx: AuthContext, script_id: uuid.UUID) -> Script:
    sc = db.get(Script, script_id)
    if sc is None or sc.organization_id != ctx.user.organization_id or not tenancy.can_see(ctx, sc.owner_admin_id):
        raise HTTPException(404, "Script not found")
    return sc


@router.get("/scripts", response_model=list[s.ScriptSummaryOut])
def list_scripts(ctx: AuthContext = Depends(SHELL), db: Session = Depends(get_db)):
    q = tenancy.restrict(select(Script).where(Script.organization_id == ctx.user.organization_id),
                         Script.owner_admin_id, ctx).order_by(Script.name)
    return list(db.scalars(q).all())


@router.post("/scripts", response_model=s.ScriptOut, status_code=201)
def create_script(body: s.ScriptCreate, ctx: AuthContext = Depends(SHELL), db: Session = Depends(get_db)):
    try:
        sc = scripts.create_script(db, ctx.user.organization_id, ctx.actor, name=body.name.strip(),
                                   description=body.description, interpreter=body.interpreter, content=body.content,
                                   timeout_seconds=body.timeout_seconds, owner_admin_id=tenancy.owner_for(ctx))
    except PolicyError as e:
        _raise(e)
    return sc


@router.get("/scripts/{script_id}", response_model=s.ScriptOut)
def get_script(script_id: uuid.UUID, ctx: AuthContext = Depends(SHELL), db: Session = Depends(get_db)):
    return _get_script(db, ctx, script_id)


@router.put("/scripts/{script_id}", response_model=s.ScriptOut)
def update_script(script_id: uuid.UUID, body: s.ScriptUpdate, ctx: AuthContext = Depends(SHELL),
                  db: Session = Depends(get_db)):
    sc = _get_script(db, ctx, script_id)
    try:
        return scripts.update_script(db, sc, ctx.actor, name=body.name.strip(), description=body.description,
                                     interpreter=body.interpreter, content=body.content,
                                     timeout_seconds=body.timeout_seconds)
    except PolicyError as e:
        _raise(e)


@router.delete("/scripts/{script_id}", status_code=204)
def delete_script(script_id: uuid.UUID, ctx: AuthContext = Depends(SHELL), db: Session = Depends(get_db)):
    sc = _get_script(db, ctx, script_id)
    scripts.delete_script(db, sc, ctx.actor)


@router.post("/scripts/{script_id}/deploy", response_model=list[s.ScriptRunOut], status_code=201,
             dependencies=[Depends(rate_limit("script-deploy", 30))])
def deploy_script(script_id: uuid.UUID, body: s.ScriptDeployRequest, ctx: AuthContext = Depends(SHELL),
                  db: Session = Depends(get_db)):
    sc = _get_script(db, ctx, script_id)
    targets = [get_device(db, ctx, did) for did in dict.fromkeys(body.device_ids)]  # scope-checked, de-duplicated
    try:
        return scripts.deploy(db, sc, targets, body.reason.strip(), ctx.actor)
    except PolicyError as e:
        _raise(e)


@router.get("/scripts/{script_id}/runs", response_model=list[s.ScriptRunOut])
def script_runs(script_id: uuid.UUID, ctx: AuthContext = Depends(SHELL), db: Session = Depends(get_db)):
    _get_script(db, ctx, script_id)
    return scripts.list_runs(db, script_id=script_id, org_id=ctx.user.organization_id)


@router.get("/devices/{device_id}/script-runs", response_model=list[s.ScriptRunOut])
def device_script_runs(device_id: uuid.UUID, ctx: AuthContext = Depends(SHELL), db: Session = Depends(get_db)):
    get_device(db, ctx, device_id)  # scope check
    return scripts.list_runs(db, device_id=device_id, org_id=ctx.user.organization_id, limit=50)
