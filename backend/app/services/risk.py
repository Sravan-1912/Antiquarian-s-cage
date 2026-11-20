"""Continuous per-endpoint risk scoring.

A single 0–100 number that synthesises the signals the platform already produces — compliance posture, open security
alerts / EDR detections, and connectivity — so an operator can triage a fleet at a glance. Higher = riskier. Computed
on demand (cheap) from current state; no new storage.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Device, SecurityAlert
from app.services import compliance, devices
from app.services.alerts import OPEN

# Points added to the risk score per open alert, by severity (capped below).
_SEV_WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 0}
_ALERT_CAP = 60          # open alerts contribute at most this much
_COMPLIANCE_WEIGHT = 0.4  # a 0%-compliant device adds 40; a 100%-compliant device adds 0
_UNEVALUATED = 20         # unknown posture is a moderate risk, never zero


@dataclass
class Factor:
    factor: str
    detail: str
    points: int


def _level(score: int) -> str:
    return "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"


def device_risk(db: Session, device: Device) -> dict:
    factors: list[Factor] = []
    score = 0

    ev = compliance.latest_evaluation(db, device.id)
    if ev is None:
        score += _UNEVALUATED
        factors.append(Factor("compliance", "not yet evaluated", _UNEVALUATED))
    else:
        pts = round((100 - ev.score) * _COMPLIANCE_WEIGHT)
        if pts:
            factors.append(Factor("compliance", f"{ev.score}% compliant ({ev.state})", pts))
        score += pts

    rows = db.execute(
        select(SecurityAlert.severity, func.count()).where(
            SecurityAlert.device_id == device.id, SecurityAlert.status.in_(OPEN)
        ).group_by(SecurityAlert.severity)
    ).all()
    alert_pts = min(_ALERT_CAP, sum(_SEV_WEIGHT.get(sev, 0) * n for sev, n in rows))
    total_alerts = sum(n for _, n in rows)
    if alert_pts:
        worst = min((sev for sev, _ in rows), key=lambda s: list(_SEV_WEIGHT).index(s) if s in _SEV_WEIGHT else 99)
        factors.append(Factor("alerts", f"{total_alerts} open alert(s), worst: {worst}", alert_pts))
    score += alert_pts

    if devices.connectivity(device) != "online":
        score += 5
        factors.append(Factor("connectivity", "endpoint offline", 5))

    score = min(100, score)
    return {"score": score, "level": _level(score),
            "factors": [{"factor": f.factor, "detail": f.detail, "points": f.points} for f in factors]}
