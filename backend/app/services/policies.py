"""Policy engine and command jobs.

Workflow: admin creates/updates a policy (validated, versioned) → assigns devices → a deployment + signed command
job is created per device → the agent pulls jobs over its authenticated channel, validates signature/expiry/
device/version, applies through the privileged broker, and reports the result + previous state → the deployment
status is updated. Removing an assignment issues a signed `policy.remove` job that restores the recorded state."""
from __future__ import annotations

import secrets
import uuid
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utcnow
from app.models import CommandJob, Device, EndpointPolicy, PolicyAssignment, PolicyDeployment, PolicyRevision
from app.schemas.policies import validate_config
from app.security import command_signing
from app.services import audit, devices, notifications
from app.services.audit import Actor

# Server-side command allowlist with per-command lifetime (minutes). The agent and broker each enforce their own
# (identical or narrower) allowlists. There is deliberately no generic "run" command.
COMMAND_TTL_MINUTES: dict[str, int | None] = {
    "policy.apply": None, "policy.remove": None,           # None → COMMAND_JOB_TTL_HOURS
    "device.inspect": 10, "device.lock": 10, "device.restart": 30, "device.restart_cancel": 30,
    "account.disable": 60, "account.enable": 60, "account.remove_admin": 60,
    "assist.start": 10, "assist.end": 30,
}
COMMANDS = set(COMMAND_TTL_MINUTES)


class PolicyError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


# --------------------------------------------------------------------------------------------- policies
def create_policy(db: Session, org_id: uuid.UUID, actor: Actor, *, name: str, description: str, category: str,
                  configuration: dict, owner_admin_id: uuid.UUID | None = None) -> EndpointPolicy:
    cfg = validate_config(category, configuration)
    if db.scalar(select(EndpointPolicy.id).where(EndpointPolicy.organization_id == org_id, EndpointPolicy.name == name)):
        raise PolicyError("A policy with this name already exists", 409)
    p = EndpointPolicy(organization_id=org_id, name=name, description=description, category=category,
                       configuration=cfg, version=1, status="active", created_by=actor.user_id,
                       owner_admin_id=owner_admin_id)
    db.add(p)
    db.flush()
    db.add(PolicyRevision(policy_id=p.id, version=1, configuration=cfg, changed_by=actor.user_id))
    audit.record(db, org_id, actor, "policy.created", target_type="policy", target_id=p.id, target_label=name,
                 metadata={"category": category, "configuration": cfg})
    db.commit()
    return p


def update_policy(db: Session, policy: EndpointPolicy, actor: Actor, *, name: str | None, description: str | None,
                  configuration: dict | None) -> EndpointPolicy:
    if policy.status != "active":
        raise PolicyError("Retired policies cannot be modified", 409)
    changes: dict = {}
    if name is not None and name != policy.name:
        changes["name"] = {"from": policy.name, "to": name}
        policy.name = name
    if description is not None and description != policy.description:
        changes["description"] = "updated"
        policy.description = description
    redeploy = False
    if configuration is not None:
        cfg = validate_config(policy.category, configuration)
        if cfg != policy.configuration:
            changes["configuration"] = {"from": policy.configuration, "to": cfg}
            policy.configuration = cfg
            policy.version += 1
            db.add(PolicyRevision(policy_id=policy.id, version=policy.version, configuration=cfg, changed_by=actor.user_id))
            redeploy = True
    if not changes:
        return policy
    audit.record(db, policy.organization_id, actor, "policy.modified", target_type="policy", target_id=policy.id,
                 target_label=policy.name, metadata={"changes": changes, "version": policy.version})
    if redeploy:  # new version → deploy to every active assignment
        for a in active_assignments(db, policy.id):
            device = db.get(Device, a.device_id)
            if device and device.status == "active":
                _deploy(db, policy, device, a, "apply", actor)
    db.commit()
    return policy


def retire_policy(db: Session, policy: EndpointPolicy, actor: Actor) -> EndpointPolicy:
    if active_assignments(db, policy.id):
        raise PolicyError("Unassign all devices (with rollback) before retiring this policy", 409)
    policy.status = "retired"
    audit.record(db, policy.organization_id, actor, "policy.retired", target_type="policy", target_id=policy.id,
                 target_label=policy.name)
    db.commit()
    return policy


def active_assignments(db: Session, policy_id: uuid.UUID) -> list[PolicyAssignment]:
    return list(db.scalars(select(PolicyAssignment).where(PolicyAssignment.policy_id == policy_id,
                                                          PolicyAssignment.revoked_at.is_(None))))


# --------------------------------------------------------------------------------------------- assignments
def assign(db: Session, policy: EndpointPolicy, device_ids: list[uuid.UUID], actor: Actor) -> list[PolicyDeployment]:
    if policy.status != "active":
        raise PolicyError("Retired policies cannot be assigned", 409)
    out = []
    for did in dict.fromkeys(device_ids):
        device = db.get(Device, did)
        if device is None or device.organization_id != policy.organization_id:
            raise PolicyError(f"Endpoint {did} not found", 404)
        if device.status != "active":
            raise PolicyError(f"Endpoint {device.hostname} is {device.status}; only active endpoints can receive policies", 409)
        # One active policy per category per device avoids two policies fighting over the same setting.
        clash = db.scalar(select(EndpointPolicy.name).join(PolicyAssignment, PolicyAssignment.policy_id == EndpointPolicy.id)
                          .where(PolicyAssignment.device_id == did, PolicyAssignment.revoked_at.is_(None),
                                 EndpointPolicy.category == policy.category, EndpointPolicy.id != policy.id))
        if clash:
            raise PolicyError(f"{device.hostname} already has the {policy.category} policy “{clash}”; unassign it first", 409)
        existing = db.scalar(select(PolicyAssignment).where(PolicyAssignment.policy_id == policy.id,
                                                            PolicyAssignment.device_id == did,
                                                            PolicyAssignment.revoked_at.is_(None)))
        if existing:
            continue
        a = PolicyAssignment(policy_id=policy.id, device_id=did, assigned_by=actor.user_id)
        db.add(a)
        db.flush()
        out.append(_deploy(db, policy, device, a, "apply", actor))
    audit.record(db, policy.organization_id, actor, "policy.assigned", target_type="policy", target_id=policy.id,
                 target_label=policy.name, metadata={"device_ids": [str(d) for d in device_ids], "version": policy.version})
    db.commit()
    return out


def unassign(db: Session, policy: EndpointPolicy, device_ids: list[uuid.UUID], rollback: bool, actor: Actor) -> int:
    n = 0
    for did in dict.fromkeys(device_ids):
        a = db.scalar(select(PolicyAssignment).where(PolicyAssignment.policy_id == policy.id,
                                                     PolicyAssignment.device_id == did,
                                                     PolicyAssignment.revoked_at.is_(None)))
        if a is None:
            continue
        a.revoked_at = utcnow()
        a.revoked_by = actor.user_id
        # Revoke any still-pending apply job so it can't land after the unassignment.
        for d in db.scalars(select(PolicyDeployment).where(PolicyDeployment.assignment_id == a.id,
                                                           PolicyDeployment.status.in_(("pending", "offline")))):
            _revoke_deployment(db, d, "superseded by unassignment")
        device = db.get(Device, did)
        if rollback and device and device.status == "active":
            _deploy(db, policy, device, a, "remove", actor)
        n += 1
    audit.record(db, policy.organization_id, actor, "policy.unassigned", target_type="policy", target_id=policy.id,
                 target_label=policy.name, metadata={"device_ids": [str(d) for d in device_ids], "rollback": rollback})
    db.commit()
    return n


def redeploy(db: Session, deployment: PolicyDeployment, actor: Actor) -> PolicyDeployment:
    if deployment.status not in ("failed", "needs_attention", "offline", "revoked"):
        raise PolicyError("Only failed, offline, revoked or attention-required deployments can be retried", 409)
    policy = db.get(EndpointPolicy, deployment.policy_id)
    device = db.get(Device, deployment.device_id)
    a = db.get(PolicyAssignment, deployment.assignment_id) if deployment.assignment_id else None
    if policy is None or device is None or device.status != "active":
        raise PolicyError("Endpoint is not active", 409)
    if deployment.action == "apply" and (a is None or a.revoked_at):
        raise PolicyError("The assignment was removed; re-assign the policy instead", 409)
    d = _deploy(db, policy, device, a, deployment.action, actor)
    db.commit()
    return d


# --------------------------------------------------------------------------------------------- jobs
def _deploy(db: Session, policy: EndpointPolicy, device: Device, assignment: PolicyAssignment | None, action: str,
            actor: Actor) -> PolicyDeployment:
    params = {"policy_id": str(policy.id), "policy_name": policy.name, "category": policy.category,
              "version": policy.version, "configuration": policy.configuration}
    job = create_job(db, device, f"policy.{action}", params, actor,
                     idempotency_key=f"policy:{policy.id}:{device.id}:{action}:v{policy.version}:{secrets.token_hex(4)}")
    online = devices.connectivity(device) == "online"
    dep = PolicyDeployment(policy_id=policy.id, device_id=device.id, assignment_id=assignment.id if assignment else None,
                           policy_version=policy.version, action=action, command_job_id=job.id,
                           status="pending" if online else "offline",
                           detail=None if online else "Endpoint offline; job queued until it reconnects or expires")
    db.add(dep)
    db.flush()
    audit.record(db, device.organization_id, actor, "policy.deployment_created", target_type="device", target_id=device.id,
                 target_label=device.hostname, metadata={"policy": policy.name, "action": action,
                                                         "version": policy.version, "job_id": str(job.id)})
    return dep


def create_job(db: Session, device: Device, command: str, parameters: dict, actor: Actor, *,
               idempotency_key: str) -> CommandJob:
    if command not in COMMANDS:
        raise PolicyError(f"Command '{command}' is not on the allowlist", 400)
    now = utcnow()
    ttl = COMMAND_TTL_MINUTES[command]
    lifetime = timedelta(minutes=ttl) if ttl else timedelta(hours=get_settings().command_job_ttl_hours)
    job = CommandJob(id=uuid.uuid4(), organization_id=device.organization_id, device_id=device.id, command=command,
                     parameters=parameters, nonce=secrets.token_hex(16), idempotency_key=idempotency_key,
                     issued_at=now, expires_at=now + lifetime,
                     requested_by=actor.user_id, key_id="", signature="", status="queued")
    envelope = {
        "v": 1, "job_id": str(job.id), "device_id": str(device.id), "command": command, "parameters": parameters,
        "issued_at": now.isoformat(), "expires_at": job.expires_at.isoformat(), "nonce": job.nonce,
    }
    key_id, sig = command_signing.sign({**envelope, "key_id": command_signing.get_signing_key().key_id})
    job.key_id, job.signature = key_id, sig
    job.envelope = {**envelope, "key_id": key_id, "signature": sig}
    db.add(job)
    db.flush()
    return job


def _revoke_deployment(db: Session, d: PolicyDeployment, reason: str) -> None:
    job = db.get(CommandJob, d.command_job_id) if d.command_job_id else None
    if job and job.status in ("queued", "delivered"):
        job.status = "revoked"
        job.revoked_at = utcnow()
    d.status = "revoked"
    d.detail = reason


def revoke_job(db: Session, job: CommandJob, actor: Actor) -> CommandJob:
    """Emergency revocation: undelivered jobs are never handed out; delivered ones are listed as revoked on the
    agent's next poll and dropped if not yet executed."""
    if job.status not in ("queued", "delivered"):
        raise PolicyError(f"Job is already {job.status}", 409)
    job.status = "revoked"
    job.revoked_at = utcnow()
    for d in db.scalars(select(PolicyDeployment).where(PolicyDeployment.command_job_id == job.id)):
        d.status, d.detail = "revoked", "Command revoked by administrator"
    audit.record(db, job.organization_id, actor, "command.revoked", target_type="command_job", target_id=job.id,
                 target_label=job.command, metadata={"device_id": str(job.device_id)})
    db.commit()
    return job


def expire_jobs(db: Session, device_id: uuid.UUID | None = None) -> int:
    q = select(CommandJob).where(CommandJob.status.in_(("queued", "delivered")), CommandJob.expires_at < utcnow())
    if device_id:
        q = q.where(CommandJob.device_id == device_id)
    n = 0
    for job in db.scalars(q):
        job.status = "expired"
        for d in db.scalars(select(PolicyDeployment).where(PolicyDeployment.command_job_id == job.id)):
            d.status = "offline" if job.delivered_at is None else "needs_attention"
            d.detail = ("Job expired before the endpoint came online" if job.delivered_at is None
                        else "Job delivered but no result was reported before expiry")
        n += 1
    db.flush()  # autoflush is off: make expiries visible to the queries that follow
    return n


def fetch_jobs(db: Session, device: Device) -> dict:
    expire_jobs(db, device.id)
    now = utcnow()
    redeliver_after = now - timedelta(minutes=10)
    jobs = list(db.scalars(select(CommandJob).where(
        CommandJob.device_id == device.id,
        (CommandJob.status == "queued") | ((CommandJob.status == "delivered") & (CommandJob.delivered_at < redeliver_after)),
    ).order_by(CommandJob.issued_at).limit(20)))
    if device.status != "active":
        jobs = []  # suspended devices receive no new instructions
    for j in jobs:
        j.status = "delivered"
        j.delivered_at = now
        for d in db.scalars(select(PolicyDeployment).where(PolicyDeployment.command_job_id == j.id)):
            if d.status in ("pending", "offline"):
                d.status, d.detail = "in_progress", "Delivered to agent"
    revoked = [str(i) for i in db.scalars(select(CommandJob.id).where(
        CommandJob.device_id == device.id, CommandJob.status == "revoked",
        CommandJob.revoked_at > now - timedelta(days=7)))]
    key = command_signing.get_signing_key()
    db.commit()
    return {"jobs": [j.envelope for j in jobs], "revoked_job_ids": revoked,
            "command_key": {"key_id": key.key_id, "public_key": key.public_key_b64}}


STATUS_MAP = {"succeeded": "applied", "failed": "failed", "needs_attention": "needs_attention", "rejected": "failed"}


def record_result(db: Session, device: Device, job_id: uuid.UUID, status: str, detail: str | None,
                  previous_state: dict, current_state: dict, source_ip: str | None) -> CommandJob:
    job = db.get(CommandJob, job_id)
    if job is None or job.device_id != device.id:
        raise PolicyError("Unknown job", 404)
    if job.status not in ("delivered", "queued"):
        # Idempotent re-report of an already recorded result is fine; anything else is refused.
        if job.status in ("succeeded", "failed") and job.result.get("status") == status:
            return job
        raise PolicyError(f"Job is {job.status}; result not accepted", 409)
    job.status = "succeeded" if status == "succeeded" else "failed"
    job.completed_at = utcnow()
    job.result = {"status": status, "detail": detail, "current_state": current_state}
    if not job.command.startswith("policy."):
        from app.services import remote
        remote.on_job_result(db, device, job, status, detail, current_state, source_ip)
        db.commit()
        return job
    failed_deps = []
    for d in db.scalars(select(PolicyDeployment).where(PolicyDeployment.command_job_id == job.id)):
        d.status = STATUS_MAP[status]
        if d.action == "remove" and status == "succeeded":
            d.status = "applied"
            d.detail = "Rolled back: previous configuration restored"
        else:
            d.detail = (f"Rejected by agent: {detail}" if status == "rejected" else detail)
        d.result = {"current_state": current_state}
        if previous_state:
            d.previous_state = previous_state
        if d.status in ("failed", "needs_attention"):
            failed_deps.append(d)
    db.flush()
    from app.services import alerts
    for d in db.scalars(select(PolicyDeployment).where(PolicyDeployment.command_job_id == job.id)):
        if d.status in ("failed", "needs_attention"):
            alerts.on_deployment_failure(db, device, d.policy_id)
        elif d.status == "applied" and d.action == "apply":
            alerts.on_deployment_success(db, device, d.policy_id)
    audit.record(db, device.organization_id, devices.device_actor(device, source_ip), "policy.deployment_result",
                 target_type="command_job", target_id=job.id, target_label=job.command,
                 result="success" if status == "succeeded" else "failure",
                 metadata={"status": status, "detail": (detail or "")[:500],
                           "policy": job.parameters.get("policy_name"), "version": job.parameters.get("version")})
    if failed_deps:
        notifications.notify_users(
            db, device.organization_id, notifications.users_with_permission(db, device.organization_id, "policies:write"),
            kind="policy.deployment_failed", severity="medium",
            title=f"Policy deployment {STATUS_MAP[status].replace('_', ' ')}: {device.hostname}",
            body=f"{job.parameters.get('policy_name')} v{job.parameters.get('version')}: {(detail or '')[:200]}",
            link=f"/policies/{job.parameters.get('policy_id')}")
    db.commit()
    return job


def deployment_summary(db: Session, policy_id: uuid.UUID) -> dict[str, int]:
    """Status of the *latest* deployment per device for this policy."""
    latest = (select(PolicyDeployment.device_id, func.max(PolicyDeployment.created_at).label("m"))
              .where(PolicyDeployment.policy_id == policy_id).group_by(PolicyDeployment.device_id).subquery())
    rows = db.execute(select(PolicyDeployment.status, func.count())
                      .join(latest, (PolicyDeployment.device_id == latest.c.device_id) &
                            (PolicyDeployment.created_at == latest.c.m))
                      .where(PolicyDeployment.policy_id == policy_id).group_by(PolicyDeployment.status)).all()
    return {s: c for s, c in rows}
