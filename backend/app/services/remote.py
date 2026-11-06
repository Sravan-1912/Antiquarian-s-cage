"""Remote administration: allowlisted one-shot actions and consented remote-assistance sessions.

Every action is a signed, short-lived CommandJob that the endpoint validates; there is no arbitrary command path.
Assistance sessions require (by default) explicit consent from the person at the endpoint, show a persistent on-screen
indicator for their whole duration, expire automatically, and can be ended from either side. Every transition is
audited. The screen-sharing channel itself is Windows Quick Assist, launched only after consent."""
from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import utcnow
from app.models import CommandJob, Device, Organization, RemoteSession, User
from app.schemas.remote import ACTION_SCHEMAS, AssistSettings
from app.services import audit, devices, notifications, policies
from app.services.audit import Actor
from app.services.policies import PolicyError

TERMINAL = {"ended", "denied", "expired", "cancelled", "failed"}


def assist_settings(db: Session, org_id: uuid.UUID) -> AssistSettings:
    org = db.get(Organization, org_id)
    return AssistSettings(**((org.settings or {}).get("remote_assistance") or {})) if org else AssistSettings()


def update_assist_settings(db: Session, org_id: uuid.UUID, new: AssistSettings, actor: Actor) -> AssistSettings:
    org = db.get(Organization, org_id)
    before = assist_settings(db, org_id).model_dump()
    org.settings = {**(org.settings or {}), "remote_assistance": new.model_dump()}
    audit.record(db, org_id, actor, "org.remote_assistance_settings", target_type="organization", target_id=org_id,
                 target_label=org.name, metadata={"before": before, "after": new.model_dump()})
    db.commit()
    return new


# ----------------------------------------------------------------------------------------------- actions
def create_action(db: Session, device: Device, command: str, parameters: dict, reason: str, actor: Actor) -> CommandJob:
    if device.status != "active":
        raise PolicyError(f"Endpoint is {device.status}; remote actions require an active endpoint", 409)
    params = ACTION_SCHEMAS[command].model_validate(parameters).model_dump()
    job = policies.create_job(db, device, command, {**params, "reason": reason, "requested_by": actor.label}, actor,
                              idempotency_key=f"action:{device.id}:{command}:{uuid.uuid4().hex}")
    audit.record(db, device.organization_id, actor, f"remote.{command}", target_type="device", target_id=device.id,
                 target_label=device.hostname, metadata={"job_id": str(job.id), "reason": reason, "parameters": params,
                                                         "device_online": devices.connectivity(device) == "online"})
    db.commit()
    return job


# ----------------------------------------------------------------------------------------------- sessions
def request_session(db: Session, device: Device, reason: str, max_minutes: int, actor: Actor) -> RemoteSession:
    if device.status != "active":
        raise PolicyError(f"Endpoint is {device.status}", 409)
    if devices.connectivity(device) != "online":
        raise PolicyError("Endpoint is offline; remote assistance needs a connected endpoint", 409)
    cfg = assist_settings(db, device.organization_id)
    if max_minutes > cfg.max_session_minutes:
        raise PolicyError(f"Sessions are limited to {cfg.max_session_minutes} minutes by organisation policy", 422)
    live = db.scalar(select(RemoteSession).where(RemoteSession.device_id == device.id,
                                                 RemoteSession.status.in_(("requested", "awaiting_consent", "active", "ending"))))
    if live:
        refresh(db, live)
        if live.status not in TERMINAL:
            raise PolicyError("A remote session is already open for this endpoint", 409)
    s = RemoteSession(id=uuid.uuid4(), organization_id=device.organization_id, device_id=device.id,
                      requested_by=actor.user_id, requested_by_label=actor.label, reason=reason,
                      require_consent=cfg.require_consent, max_minutes=max_minutes, status="requested")
    db.add(s)
    db.flush()
    job = policies.create_job(db, device, "assist.start", {
        "session_id": str(s.id), "requested_by": actor.label, "reason": reason, "max_minutes": max_minutes,
        "require_consent": cfg.require_consent, "consent_timeout_seconds": 120,
    }, actor, idempotency_key=f"assist:{s.id}:start")
    s.start_job_id = job.id
    audit.record(db, device.organization_id, actor, "remote.session_requested", target_type="device",
                 target_id=device.id, target_label=device.hostname,
                 metadata={"session_id": str(s.id), "reason": reason, "max_minutes": max_minutes,
                           "require_consent": cfg.require_consent})
    notifications.notify_users(
        db, device.organization_id, notifications.users_with_permission(db, device.organization_id, "devices:manage"),
        kind="remote.session_requested", severity="medium",
        title=f"Remote assistance requested: {device.hostname}", body=f"{actor.label}: {reason}",
        link=f"/endpoints/{device.id}")
    db.commit()
    return s


def terminate(db: Session, s: RemoteSession, reason: str, actor: Actor) -> RemoteSession:
    refresh(db, s)
    if s.status in TERMINAL:
        raise PolicyError(f"Session already {s.status}", 409)
    device = db.get(Device, s.device_id)
    if s.status == "requested":
        job = db.get(CommandJob, s.start_job_id) if s.start_job_id else None
        if job and job.status == "queued":
            job.status, job.revoked_at = "revoked", utcnow()
        _close(s, "cancelled", "administrator", reason)
    else:
        job = policies.create_job(db, device, "assist.end", {"session_id": str(s.id), "reason": reason}, actor,
                                  idempotency_key=f"assist:{s.id}:end:{uuid.uuid4().hex[:6]}")
        s.end_job_id = job.id
        s.status = "ending"
        s.end_reason = reason
    audit.record(db, s.organization_id, actor, "remote.session_terminated", target_type="device", target_id=s.device_id,
                 target_label=device.hostname if device else None, metadata={"session_id": str(s.id), "reason": reason})
    db.commit()
    return s


def _cleanup_job(db: Session, s: RemoteSession, why: str) -> None:
    """Signed assist.end issued by the system after the endpoint ended/expired a session, so the privileged broker
    can close Quick Assist (which runs at high integrity and cannot be closed by the unprivileged agent)."""
    device = db.get(Device, s.device_id)
    if device is None or device.status != "active" or s.end_job_id:
        return
    job = policies.create_job(db, device, "assist.end", {"session_id": str(s.id), "reason": why}, Actor.system(),
                              idempotency_key=f"assist:{s.id}:cleanup")
    s.end_job_id = job.id


def _close(s: RemoteSession, status: str, ended_by: str, reason: str | None) -> None:
    s.status = status
    s.ended_at = utcnow()
    s.ended_by = ended_by
    s.end_reason = reason or s.end_reason


def refresh(db: Session, s: RemoteSession) -> RemoteSession:
    """Server-side enforcement of expiry and of undelivered requests (the endpoint enforces its own timer too)."""
    now = utcnow()
    if s.status in ("active", "ending") and s.expires_at and now >= s.expires_at:
        _close(s, "expired", "expiry", "Maximum session duration reached")
        _cleanup_job(db, s, "session expired")
        audit.record(db, s.organization_id, Actor.system(), "remote.session_expired", target_type="device",
                     target_id=s.device_id, metadata={"session_id": str(s.id)})
    elif s.status in ("requested", "awaiting_consent") and s.start_job_id:
        job = db.get(CommandJob, s.start_job_id)
        # consent prompt waits up to 2 min after delivery; allow generous slack for slow endpoints
        if job and (job.status in ("expired", "revoked") or
                    (job.delivered_at and now - job.delivered_at > timedelta(minutes=5) and job.status == "delivered")):
            _close(s, "failed", "system", "Endpoint did not respond to the session request")
    return s


def on_job_result(db: Session, device: Device, job: CommandJob, status: str, detail: str | None, state: dict,
                  source_ip: str | None) -> None:
    actor = devices.device_actor(device, source_ip)
    if job.command == "assist.start":
        s = db.get(RemoteSession, uuid.UUID(job.parameters["session_id"]))
        if s is None or s.device_id != device.id or s.status in TERMINAL:
            return
        decision = state.get("consent") if status == "succeeded" else None
        s.consent_decision = decision or ("error" if status != "succeeded" else None)
        s.consent_user = str(state.get("consent_user") or "")[:128] or None
        if status == "succeeded" and decision in ("granted", "not_required"):
            now = utcnow()
            s.status, s.consented_at, s.started_at = "active", now, now
            s.expires_at = now + timedelta(minutes=s.max_minutes)
            action = "remote.session_started"
        elif status == "succeeded" and decision in ("denied", "timeout"):
            _close(s, "denied", "endpoint_user", "Consent " + ("declined" if decision == "denied" else "not given in time"))
            action = "remote.session_denied"
        else:
            _close(s, "failed", "system", detail or "Endpoint could not start the session")
            action = "remote.session_failed"
        audit.record(db, device.organization_id, actor, action, target_type="device", target_id=device.id,
                     target_label=device.hostname, result="success" if s.status == "active" else "failure",
                     metadata={"session_id": str(s.id), "consent": decision, "consent_user": s.consent_user,
                               "detail": (detail or "")[:300]})
        return
    if job.command == "assist.end":
        s = db.get(RemoteSession, uuid.UUID(job.parameters["session_id"]))
        if s is None:
            return
        if s.status not in TERMINAL:
            _close(s, "ended", "administrator", s.end_reason)
        if status != "succeeded":  # session is over, but the sharing tool may still be open: say so loudly
            s.end_reason = f"{s.end_reason or ''} — cleanup incomplete: {detail}".strip(" —")
            notifications.notify_users(
                db, device.organization_id, notifications.users_with_permission(db, device.organization_id,
                                                                                 "devices:remote"),
                kind="remote.cleanup_incomplete", severity="high",
                title=f"Remote session cleanup incomplete: {device.hostname}", body=(detail or "")[:300],
                link=f"/endpoints/{device.id}")
        audit.record(db, device.organization_id, actor, "remote.session_ended", target_type="device",
                     target_id=device.id, target_label=device.hostname,
                     result="success" if status == "succeeded" else "failure",
                     metadata={"session_id": str(s.id), "cleanup": status, "detail": (detail or "")[:300]})
        return
    audit.record(db, device.organization_id, actor, f"remote.{job.command}.result", target_type="command_job",
                 target_id=job.id, target_label=job.command, result="success" if status == "succeeded" else "failure",
                 metadata={"status": status, "detail": (detail or "")[:500]})


def on_agent_event(db: Session, device: Device, session_id: uuid.UUID, event: str, detail: str | None,
                   source_ip: str | None) -> RemoteSession:
    s = db.get(RemoteSession, session_id)
    if s is None or s.device_id != device.id:
        raise PolicyError("Unknown session", 404)
    if s.status not in TERMINAL:
        status, by = {"ended_by_user": ("ended", "endpoint_user"), "expired": ("expired", "expiry"),
                      "terminated": ("ended", "administrator"), "helper_failed": ("failed", "system")}[event]
        _close(s, status, by, detail)
        if event in ("ended_by_user", "expired"):
            _cleanup_job(db, s, f"session {event.replace('_', ' ')}")
        audit.record(db, device.organization_id, devices.device_actor(device, source_ip), f"remote.session_{status}",
                     target_type="device", target_id=device.id, target_label=device.hostname,
                     metadata={"session_id": str(s.id), "event": event, "detail": (detail or "")[:300]})
        db.commit()
    return s


def requester_label(db: Session, user_id: uuid.UUID | None) -> str | None:
    u = db.get(User, user_id) if user_id else None
    return u.email if u else None
