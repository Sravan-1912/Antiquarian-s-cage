"""Automated response (SOAR): when a NEW security alert matches a playbook's trigger, run its actions.

Evaluated once per newly-created alert (not on de-duplicated re-occurrences, so a device is never isolated twice for
the same alert). Every action is best-effort and recorded on the alert's timeline for audit. Supported actions:
  isolate  — network-isolate the endpoint the alert is about (if it is an active, managed device)
  escalate — raise the alert to critical severity and notify
  comment  — add a note to the alert timeline
"""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AlertEvent, Device, ResponsePlaybook, SecurityAlert

log = logging.getLogger("app.playbooks")
ACTIONS = ("isolate", "escalate", "comment")
_SEV = ("critical", "high", "medium", "low", "informational")


def _matches(pb: ResponsePlaybook, alert: SecurityAlert) -> bool:
    if pb.match_rule_keys and alert.rule_key not in pb.match_rule_keys:
        return False
    if pb.match_kinds and alert.kind not in pb.match_kinds:
        return False
    # alert must be at least as severe as the playbook's minimum
    return _SEV.index(alert.severity) <= _SEV.index(pb.match_min_severity)


def evaluate(db: Session, alert: SecurityAlert) -> None:
    """Run every enabled playbook that matches this new alert. Best-effort; never raises to the alert pipeline."""
    pbs = db.scalars(select(ResponsePlaybook).where(ResponsePlaybook.organization_id == alert.organization_id,
                                                    ResponsePlaybook.enabled.is_(True))).all()
    for pb in pbs:
        if _matches(pb, alert):
            _run(db, pb, alert)


def _run(db: Session, pb: ResponsePlaybook, alert: SecurityAlert) -> None:
    done: list[str] = []
    for action in pb.actions:
        try:
            if action == "isolate" and alert.device_id:
                dev = db.get(Device, alert.device_id)
                if dev is not None and dev.status == "active":
                    from app.services import audit, remote
                    remote.create_action(db, dev, "device.isolate", {},
                                         reason=f"Automated response — playbook '{pb.name}'",
                                         actor=audit.Actor(type="system", user_id=None, label=f"playbook:{pb.name}"))
                    done.append("isolate")
            elif action == "escalate" and alert.severity != "critical":
                alert.severity = "critical"
                from app.services import alerts as alerts_svc
                alerts_svc._notify(db, alert)  # noqa: SLF001 — escalation must page even if it was below threshold
                done.append("escalate")
            elif action == "comment":
                done.append("comment")
        except Exception as exc:  # noqa: BLE001 — one failed action never blocks the others or the alert
            log.warning("playbook '%s' action '%s' failed on alert %s: %s", pb.name, action, alert.id, exc)
    if done:
        db.add(AlertEvent(alert_id=alert.id, kind="playbook", actor_label=f"playbook:{pb.name}",
                          details={"actions": done, "playbook": pb.name}))
