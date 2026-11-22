"""Per-endpoint activity timeline: a unified, read-only feed merged from the history that already exists across the
platform — device lifecycle events, security alerts, remote actions (command jobs), remote-assistance/RDP/shell
sessions and script runs. Nothing new is stored; this composes a single reverse-chronological view on demand.

Each entry is a small typed dict: {at, category, severity, title, detail, ref_id}. The console renders an icon and a
colour from `category` + `severity`. Results are scope-checked by the caller (the device must be visible to them).
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import CommandJob, DeviceEvent, RemoteSession, ScriptRun, SecurityAlert, User

# Friendly titles for the lifecycle events the agent/console record on a device.
_EVENT_TITLES = {
    "enrolled": "Endpoint enrolled", "came_online": "Came online", "hostname_changed": "Hostname changed",
    "agent_version_changed": "Agent updated", "certificate_renewed": "Certificate renewed",
    "usb_storage_connected": "USB storage connected", "usb_storage_disconnected": "USB storage removed",
    "updated": "Details updated", "suspended": "Suspended", "unsuspended": "Reactivated",
    "revoked": "Revoked", "assigned": "Assignment changed",
}
_REMOTE_LABELS = {"assist": "Remote assistance", "rdp": "Remote desktop", "shell": "Live-response shell"}


def _entry(at: datetime | None, category: str, title: str, detail: str = "", severity: str | None = None,
           ref_id: uuid.UUID | None = None) -> dict | None:
    if at is None:
        return None
    return {"at": at, "category": category, "severity": severity, "title": title,
            "detail": detail[:300], "ref_id": str(ref_id) if ref_id else None}


def device_timeline(db: Session, device_id: uuid.UUID, *, limit: int = 100, per_source: int = 60) -> list[dict]:
    entries: list[dict] = []

    # --- lifecycle / inventory events -------------------------------------------------------------------------
    evs = db.scalars(select(DeviceEvent).where(DeviceEvent.device_id == device_id)
                     .order_by(DeviceEvent.created_at.desc()).limit(per_source)).all()
    actor_ids = {e.actor_id for e in evs if e.actor_id}
    actors = dict(db.execute(select(User.id, User.email).where(User.id.in_(actor_ids))).all()) if actor_ids else {}
    for e in evs:
        title = _EVENT_TITLES.get(e.kind, e.kind.replace("_", " ").capitalize())
        who = actors.get(e.actor_id)
        det = []
        d = e.details or {}
        if e.kind in ("hostname_changed", "agent_version_changed") and d.get("from") is not None:
            det.append(f"{d.get('from')} → {d.get('to')}")
        elif e.kind in ("usb_storage_connected", "usb_storage_disconnected") and d.get("device"):
            det.append(str(d["device"]))
        if who:
            det.append(f"by {who}")
        cat = "removable" if e.kind.startswith("usb_storage") else "lifecycle"
        entries.append(_entry(e.created_at, cat, title, " · ".join(det), ref_id=e.id))

    # --- security alerts ---------------------------------------------------------------------------------------
    for a in db.scalars(select(SecurityAlert).where(SecurityAlert.device_id == device_id)
                        .order_by(SecurityAlert.created_at.desc()).limit(per_source)).all():
        entries.append(_entry(a.created_at, "alert", a.title, f"{a.severity} · {a.status}",
                              severity=a.severity, ref_id=a.id))

    # --- remote actions (command jobs), excluding session/script plumbing --------------------------------------
    jobs = db.scalars(
        select(CommandJob).where(CommandJob.device_id == device_id,
                                 CommandJob.command.not_like("policy.%"),
                                 CommandJob.command.not_in(("script.run", "assist.start", "assist.end",
                                                           "rdp.start", "rdp.end", "shell.start", "shell.end")))
        .order_by(CommandJob.issued_at.desc()).limit(per_source)).all()
    for j in jobs:
        who = j.parameters.get("requested_by") if isinstance(j.parameters, dict) else None
        reason = j.parameters.get("reason") if isinstance(j.parameters, dict) else None
        detail = " · ".join([p for p in (j.status, reason, f"by {who}" if who else None) if p])
        sev = "high" if j.status in ("failed", "needs_attention") else None
        entries.append(_entry(j.completed_at or j.issued_at, "action", j.command, detail, severity=sev, ref_id=j.id))

    # --- remote sessions ---------------------------------------------------------------------------------------
    for sdb in db.scalars(select(RemoteSession).where(RemoteSession.device_id == device_id)
                         .order_by(RemoteSession.created_at.desc()).limit(per_source)).all():
        label = _REMOTE_LABELS.get(sdb.mode, "Remote session")
        detail = " · ".join([p for p in (sdb.status, sdb.reason, f"by {sdb.requested_by_label}") if p])
        entries.append(_entry(sdb.ended_at or sdb.started_at or sdb.created_at, "remote", label, detail,
                              ref_id=sdb.id))

    # --- script runs -------------------------------------------------------------------------------------------
    for r in db.scalars(select(ScriptRun).where(ScriptRun.device_id == device_id)
                       .order_by(ScriptRun.created_at.desc()).limit(per_source)).all():
        bits = [r.status]
        if r.exit_code is not None:
            bits.append(f"exit {r.exit_code}")
        if r.requested_by_label:
            bits.append(f"by {r.requested_by_label}")
        sev = "high" if r.status in ("failed", "needs_attention", "rejected") else None
        entries.append(_entry(r.finished_at or r.created_at, "script", f"Script: {r.script_name}",
                              " · ".join(bits), severity=sev, ref_id=r.id))

    entries = [e for e in entries if e is not None]
    entries.sort(key=lambda e: e["at"], reverse=True)
    return entries[:limit]
