"""Admin API: endpoint security policies, deployments, command jobs and compliance."""
from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, require_permission
from app.core.database import get_db, utcnow
from app.models import (
    CommandJob, ComplianceCheckSetting, ComplianceEvaluation, ComplianceResult, Device, EndpointPolicy,
    PolicyAssignment, PolicyDeployment, PolicyRevision,
)
from app.schemas import policies as s
from app.services import audit, compliance, policies, tenancy
from app.services.policies import PolicyError

router = APIRouter(tags=["security"])
READ = require_permission("policies:read")
WRITE = require_permission("policies:write")
COMPLIANCE = require_permission("compliance:read")


def _raise(e: PolicyError):
    raise HTTPException(e.status, e.message)


def _validation(exc: ValidationError):
    raise HTTPException(422, detail=[{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()])


def _policy(db: Session, ctx: AuthContext, pid: uuid.UUID) -> EndpointPolicy:
    p = db.get(EndpointPolicy, pid)
    if p is None or p.organization_id != ctx.user.organization_id or not tenancy.can_see(ctx, p.owner_admin_id):
        raise HTTPException(404, "Policy not found")
    return p


def _out(db: Session, p: EndpointPolicy) -> s.PolicyOut:
    o = s.PolicyOut.model_validate(p)
    o.assigned_devices = len(policies.active_assignments(db, p.id))
    o.deployment_summary = policies.deployment_summary(db, p.id)
    return o


def _dep_out(db: Session, d: PolicyDeployment) -> s.DeploymentOut:
    o = s.DeploymentOut.model_validate(d)
    dev = db.get(Device, d.device_id)
    pol = db.get(EndpointPolicy, d.policy_id)
    o.device_name = dev.display_name if dev else None
    o.policy_name = pol.name if pol else None
    return o


# ------------------------------------------------------------------------------------------------ policies
@router.get("/policies/schema")
def policy_schemas(ctx: AuthContext = Depends(READ)):
    return {k: m.model_json_schema() for k, m in s.CONFIG_MODELS.items()}


@router.get("/policies", response_model=list[s.PolicyOut])
def list_policies(category: s.Category | None = None, include_retired: bool = False,
                  ctx: AuthContext = Depends(READ), db: Session = Depends(get_db)):
    q = tenancy.restrict(select(EndpointPolicy).where(EndpointPolicy.organization_id == ctx.user.organization_id),
                         EndpointPolicy.owner_admin_id, ctx)
    if category:
        q = q.where(EndpointPolicy.category == category)
    if not include_retired:
        q = q.where(EndpointPolicy.status == "active")
    return [_out(db, p) for p in db.scalars(q.order_by(EndpointPolicy.category, EndpointPolicy.name))]


@router.post("/policies", response_model=s.PolicyOut, status_code=201)
def create_policy(body: s.PolicyCreate, ctx: AuthContext = Depends(WRITE), db: Session = Depends(get_db)):
    try:
        p = policies.create_policy(db, ctx.user.organization_id, ctx.actor, name=body.name.strip(),
                                   description=body.description.strip(), category=body.category,
                                   configuration=body.configuration, owner_admin_id=tenancy.owner_for(ctx))
    except ValidationError as exc:
        _validation(exc)
    except PolicyError as e:
        _raise(e)
    return _out(db, p)


@router.get("/policies/{pid}", response_model=s.PolicyOut)
def get_policy(pid: uuid.UUID, ctx: AuthContext = Depends(READ), db: Session = Depends(get_db)):
    return _out(db, _policy(db, ctx, pid))


@router.patch("/policies/{pid}", response_model=s.PolicyOut)
def update_policy(pid: uuid.UUID, body: s.PolicyUpdate, ctx: AuthContext = Depends(WRITE), db: Session = Depends(get_db)):
    p = _policy(db, ctx, pid)
    try:
        policies.update_policy(db, p, ctx.actor, name=body.name, description=body.description,
                               configuration=body.configuration)
    except ValidationError as exc:
        _validation(exc)
    except PolicyError as e:
        _raise(e)
    return _out(db, p)


@router.post("/policies/{pid}/retire", response_model=s.PolicyOut)
def retire_policy(pid: uuid.UUID, ctx: AuthContext = Depends(WRITE), db: Session = Depends(get_db)):
    try:
        return _out(db, policies.retire_policy(db, _policy(db, ctx, pid), ctx.actor))
    except PolicyError as e:
        _raise(e)


@router.get("/policies/{pid}/revisions")
def revisions(pid: uuid.UUID, ctx: AuthContext = Depends(READ), db: Session = Depends(get_db)):
    _policy(db, ctx, pid)
    return [{"version": r.version, "configuration": r.configuration, "changed_by": r.changed_by,
             "created_at": r.created_at} for r in db.scalars(select(PolicyRevision).where(PolicyRevision.policy_id == pid)
                                                             .order_by(PolicyRevision.version.desc()))]


@router.get("/policies/{pid}/assignments", response_model=list[s.AssignmentOut])
def assignments(pid: uuid.UUID, ctx: AuthContext = Depends(READ), db: Session = Depends(get_db)):
    _policy(db, ctx, pid)
    out = []
    for a in db.scalars(select(PolicyAssignment).where(PolicyAssignment.policy_id == pid, PolicyAssignment.revoked_at.is_(None))):
        o = s.AssignmentOut.model_validate(a)
        dev = db.get(Device, a.device_id)
        o.device_name = dev.display_name if dev else None
        last = db.scalar(select(PolicyDeployment.status).where(PolicyDeployment.policy_id == pid,
                                                                PolicyDeployment.device_id == a.device_id)
                         .order_by(PolicyDeployment.created_at.desc()).limit(1))
        o.latest_status = last
        out.append(o)
    return out


@router.post("/policies/{pid}/assign", response_model=list[s.DeploymentOut])
def assign(pid: uuid.UUID, body: s.AssignRequest, ctx: AuthContext = Depends(WRITE), db: Session = Depends(get_db)):
    try:
        deps = policies.assign(db, _policy(db, ctx, pid), body.device_ids, ctx.actor)
    except PolicyError as e:
        _raise(e)
    return [_dep_out(db, d) for d in deps]


@router.post("/policies/{pid}/unassign")
def unassign(pid: uuid.UUID, body: s.UnassignRequest, ctx: AuthContext = Depends(WRITE), db: Session = Depends(get_db)):
    n = policies.unassign(db, _policy(db, ctx, pid), body.device_ids, body.rollback, ctx.actor)
    return {"unassigned": n}


@router.get("/deployments", response_model=list[s.DeploymentOut])
def list_deployments(policy_id: uuid.UUID | None = None, device_id: uuid.UUID | None = None,
                     status: Literal["pending", "in_progress", "applied", "failed", "offline", "needs_attention",
                                     "revoked"] | None = None,
                     limit: int = Query(100, ge=1, le=500),
                     ctx: AuthContext = Depends(READ), db: Session = Depends(get_db)):
    q = (select(PolicyDeployment).join(EndpointPolicy, EndpointPolicy.id == PolicyDeployment.policy_id)
         .where(EndpointPolicy.organization_id == ctx.user.organization_id))
    if policy_id:
        q = q.where(PolicyDeployment.policy_id == policy_id)
    if device_id:
        q = q.where(PolicyDeployment.device_id == device_id)
    if status:
        q = q.where(PolicyDeployment.status == status)
    return [_dep_out(db, d) for d in db.scalars(q.order_by(PolicyDeployment.created_at.desc()).limit(limit))]


@router.post("/deployments/{did}/retry", response_model=s.DeploymentOut)
def retry(did: uuid.UUID, ctx: AuthContext = Depends(WRITE), db: Session = Depends(get_db)):
    d = db.get(PolicyDeployment, did)
    if d is None or _policy(db, ctx, d.policy_id) is None:
        raise HTTPException(404, "Deployment not found")
    try:
        return _dep_out(db, policies.redeploy(db, d, ctx.actor))
    except PolicyError as e:
        _raise(e)


@router.post("/command-jobs/{jid}/revoke")
def revoke_job(jid: uuid.UUID, ctx: AuthContext = Depends(require_permission("policies:write", "devices:manage")),
               db: Session = Depends(get_db)):
    job = db.get(CommandJob, jid)
    if job is None or job.organization_id != ctx.user.organization_id:
        raise HTTPException(404, "Job not found")
    try:
        j = policies.revoke_job(db, job, ctx.actor)
    except PolicyError as e:
        _raise(e)
    return {"id": str(j.id), "status": j.status}


# ------------------------------------------------------------------------------------------------ compliance
@router.get("/compliance/checks")
def compliance_checks(ctx: AuthContext = Depends(COMPLIANCE), db: Session = Depends(get_db)):
    return [{"key": c.key, "name": c.name, "description": c.description, "remediation": c.remediation,
             "default_severity": c.severity, "severity": sev, "enabled": en}
            for c, en, sev in compliance.effective_checks(db, ctx.user.organization_id)]


@router.put("/compliance/checks/{key}")
def update_check(key: str, body: s.ComplianceSettingUpdate, ctx: AuthContext = Depends(WRITE),
                 db: Session = Depends(get_db)):
    if key not in compliance.CHECK_KEYS:
        raise HTTPException(404, "Unknown check")
    org = ctx.user.organization_id
    row = db.scalar(select(ComplianceCheckSetting).where(ComplianceCheckSetting.organization_id == org,
                                                         ComplianceCheckSetting.check_key == key))
    before = {"enabled": row.enabled, "severity": row.severity} if row else "default"
    if row is None:
        row = ComplianceCheckSetting(organization_id=org, check_key=key, enabled=body.enabled, severity=body.severity)
        db.add(row)
    row.enabled, row.severity, row.updated_by = body.enabled, body.severity, ctx.user.id
    audit.record(db, org, ctx.actor, "compliance.check_updated", target_type="compliance_check", target_label=key,
                 metadata={"before": before, "after": body.model_dump()})
    db.commit()
    return {"key": key, **body.model_dump()}


def _managed(ctx: AuthContext):
    own = (Device.owner_admin_id == tenancy.scope_admin_id(ctx),) if tenancy.scope_admin_id(ctx) is not None else ()
    return (Device.organization_id == ctx.user.organization_id, Device.status.in_(("active", "suspended")), *own)


@router.get("/compliance/summary")
def compliance_summary(ctx: AuthContext = Depends(COMPLIANCE), db: Session = Depends(get_db)):
    org = ctx.user.organization_id
    states = dict(db.execute(select(Device.compliance_state, func.count()).where(*_managed(ctx))
                             .group_by(Device.compliance_state)).all())
    devices = db.scalars(select(Device.id).where(*_managed(ctx))).all()
    latest = list(compliance.latest_evaluations(db, list(devices)).values())
    failing: dict[str, int] = {}
    unknown: dict[str, int] = {}
    if latest:
        counts = db.execute(select(ComplianceResult.check_key, ComplianceResult.result, func.count())
                            .where(ComplianceResult.evaluation_id.in_([e.id for e in latest]),
                                   ComplianceResult.result.in_(("FAIL", "UNKNOWN")))
                            .group_by(ComplianceResult.check_key, ComplianceResult.result)).all()
        for key, result, n in counts:
            (failing if result == "FAIL" else unknown)[key] = n
    names = {c.key: c.name for c in compliance.catalogue()}
    return {
        "devices": len(devices),
        "evaluated": len(latest),
        "states": {"compliant": states.get("compliant", 0), "non_compliant": states.get("non_compliant", 0),
                   "unknown": states.get("unknown", 0)},
        "average_score": round(sum(e.score for e in latest) / len(latest)) if latest else None,
        "failing_checks": sorted([{"key": k, "name": names.get(k, k), "devices": v} for k, v in failing.items()],
                                 key=lambda x: -x["devices"]),
        "unknown_checks": sorted([{"key": k, "name": names.get(k, k), "devices": v} for k, v in unknown.items()],
                                 key=lambda x: -x["devices"]),
        "history": compliance.org_history(db, org, 30),
    }


@router.get("/compliance/devices")
def compliance_devices(ctx: AuthContext = Depends(COMPLIANCE), db: Session = Depends(get_db)):
    out = []
    devices = db.scalars(select(Device).where(*_managed(ctx)).order_by(Device.hostname)).all()
    latest = compliance.latest_evaluations(db, [d.id for d in devices])
    for d in devices:
        e = latest.get(d.id)
        out.append({"device_id": str(d.id), "name": d.display_name, "state": d.compliance_state,
                    "score": e.score if e else None, "failed": e.failed if e else None,
                    "unknown": e.unknown if e else None, "evaluated_at": e.evaluated_at if e else None})
    return out


@router.get("/compliance/devices/{device_id}")
def device_compliance(device_id: uuid.UUID, ctx: AuthContext = Depends(COMPLIANCE), db: Session = Depends(get_db)):
    d = db.get(Device, device_id)
    if d is None or d.organization_id != ctx.user.organization_id:
        raise HTTPException(404, "Endpoint not found")
    e = compliance.latest_evaluation(db, d.id)
    cat = {c.key: c for c in compliance.catalogue()}
    results = [] if e is None else [
        {"key": r.check_key, "name": cat[r.check_key].name if r.check_key in cat else r.check_key, "result": r.result,
         "severity": r.severity, "evidence": r.evidence,
         "remediation": cat[r.check_key].remediation if r.check_key in cat and r.result != "PASS" else None}
        for r in db.scalars(select(ComplianceResult).where(ComplianceResult.evaluation_id == e.id))]
    order = {"FAIL": 0, "UNKNOWN": 1, "PASS": 2, "NOT_APPLICABLE": 3}
    results.sort(key=lambda r: (order[r["result"]], r["name"]))
    since = utcnow() - timedelta(days=30)
    history = [{"evaluated_at": h.evaluated_at, "score": h.score, "state": h.state}
               for h in db.scalars(select(ComplianceEvaluation).where(ComplianceEvaluation.device_id == d.id,
                                                                     ComplianceEvaluation.evaluated_at >= since)
                                   .order_by(ComplianceEvaluation.evaluated_at))]
    return {"device_id": str(d.id), "state": d.compliance_state,
            "evaluation": None if e is None else {"evaluated_at": e.evaluated_at, "score": e.score, "passed": e.passed,
                                                  "failed": e.failed, "unknown": e.unknown,
                                                  "not_applicable": e.not_applicable},
            "results": results, "history": history}
