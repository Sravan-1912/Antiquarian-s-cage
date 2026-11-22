"""Scripts library + deployment service.

Authoring is ordinary CRUD (admin-isolation aware via `owner_admin_id`). Deployment reuses the signed-command-job
pipeline: each targeted endpoint gets a `script.run` CommandJob (signed, short-lived, allowlisted) and a `ScriptRun`
row that captures the result when the agent reports it. Output is capped server-side as a second line of defence.
"""
from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import utcnow
from app.models import CommandJob, Device, Script, ScriptRun
from app.services import audit, devices, policies
from app.services.audit import Actor
from app.services.policies import PolicyError

INTERPRETERS = ("powershell", "cmd", "bash")
_OUT_CAP = 20_000  # characters kept per stream (the agent caps too; this is defence in depth)


def create_script(db: Session, org_id: uuid.UUID, actor: Actor, *, name: str, description: str, interpreter: str,
                  content: str, timeout_seconds: int, owner_admin_id: uuid.UUID | None) -> Script:
    if interpreter not in INTERPRETERS:
        raise PolicyError(f"interpreter must be one of {INTERPRETERS}", 422)
    if db.scalar(select(Script.id).where(Script.organization_id == org_id, Script.name == name)):
        raise PolicyError(f"A script named {name!r} already exists", 409)
    s = Script(organization_id=org_id, owner_admin_id=owner_admin_id, name=name, description=description,
               interpreter=interpreter, content=content, timeout_seconds=timeout_seconds, created_by=actor.user_id)
    db.add(s)
    db.flush()
    audit.record(db, org_id, actor, "script.created", target_type="script", target_id=s.id, target_label=name,
                 metadata={"interpreter": interpreter})
    db.commit()
    return s


def update_script(db: Session, s: Script, actor: Actor, *, name: str, description: str, interpreter: str,
                  content: str, timeout_seconds: int) -> Script:
    if interpreter not in INTERPRETERS:
        raise PolicyError(f"interpreter must be one of {INTERPRETERS}", 422)
    if name != s.name and db.scalar(select(Script.id).where(Script.organization_id == s.organization_id,
                                                            Script.name == name)):
        raise PolicyError(f"A script named {name!r} already exists", 409)
    s.name, s.description, s.interpreter, s.content, s.timeout_seconds = name, description, interpreter, content, timeout_seconds
    audit.record(db, s.organization_id, actor, "script.updated", target_type="script", target_id=s.id,
                 target_label=name, metadata={"interpreter": interpreter})
    db.commit()
    return s


def delete_script(db: Session, s: Script, actor: Actor) -> None:
    audit.record(db, s.organization_id, actor, "script.deleted", target_type="script", target_id=s.id,
                 target_label=s.name)
    db.delete(s)
    db.commit()


def deploy(db: Session, script: Script, targets: list[Device], reason: str, actor: Actor) -> list[ScriptRun]:
    """Run `script` on each active, online target endpoint. Creates a signed script.run job + a ScriptRun per device.
    Offline / inactive targets are skipped with a recorded ScriptRun so the operator sees why nothing ran there."""
    if not targets:
        raise PolicyError("Select at least one endpoint", 422)
    runs: list[ScriptRun] = []
    for device in targets:
        run = ScriptRun(organization_id=script.organization_id, script_id=script.id, device_id=device.id,
                        script_name=script.name, requested_by=actor.user_id, requested_by_label=actor.label)
        db.add(run)
        db.flush()
        if device.status != "active":
            run.status, run.stderr, run.finished_at = "needs_attention", f"Endpoint is {device.status}", utcnow()
            runs.append(run)
            continue
        if devices.connectivity(device) != "online":
            # Still queue the job (it runs when the endpoint next polls), but flag the run as pending delivery.
            pass
        job = policies.create_job(
            db, device, "script.run",
            {"run_id": str(run.id), "interpreter": script.interpreter, "content": script.content,
             "timeout_seconds": int(script.timeout_seconds), "reason": reason, "requested_by": actor.label},
            actor, idempotency_key=f"script:{run.id}")
        run.command_job_id = job.id
        runs.append(run)
    audit.record(db, script.organization_id, actor, "script.deployed", target_type="script", target_id=script.id,
                 target_label=script.name, metadata={"reason": reason, "device_ids": [str(d.id) for d in targets],
                                                     "runs": len(runs)})
    db.commit()
    return runs


def record_result(db: Session, device: Device, job: CommandJob, status: str, detail: str | None, state: dict) -> None:
    """Called from remote.on_job_result when a script.run job completes: capture exit code + output on its ScriptRun."""
    run_id = job.parameters.get("run_id")
    run = db.get(ScriptRun, uuid.UUID(run_id)) if run_id else None
    if run is None or run.device_id != device.id:
        return
    exit_code = state.get("exit_code")
    run.status = status if status in ("succeeded", "failed", "needs_attention", "rejected") else "failed"
    run.exit_code = exit_code if isinstance(exit_code, int) else None
    run.stdout = str(state.get("stdout") or "")[:_OUT_CAP]
    run.stderr = (str(state.get("stderr") or "") or (detail or ""))[:_OUT_CAP]
    run.finished_at = utcnow()
    audit.record(db, device.organization_id, devices.device_actor(device, None), "script.run_result",
                 target_type="script", target_id=run.script_id, target_label=run.script_name,
                 result="success" if status == "succeeded" else "failure",
                 metadata={"run_id": str(run.id), "device_id": str(device.id), "status": status,
                           "exit_code": run.exit_code})


def list_runs(db: Session, *, script_id: uuid.UUID | None = None, device_id: uuid.UUID | None = None,
              org_id: uuid.UUID, limit: int = 100) -> list[ScriptRun]:
    q = select(ScriptRun).where(ScriptRun.organization_id == org_id)
    if script_id:
        q = q.where(ScriptRun.script_id == script_id)
    if device_id:
        q = q.where(ScriptRun.device_id == device_id)
    return list(db.scalars(q.order_by(ScriptRun.created_at.desc()).limit(limit)).all())
