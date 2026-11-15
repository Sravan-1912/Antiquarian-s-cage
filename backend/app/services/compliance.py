"""Compliance engine.

Evaluates the agent-reported security evidence of a device against the check catalogue. Rules:
* Each check yields PASS, FAIL, UNKNOWN or NOT_APPLICABLE — UNKNOWN is never counted as compliant.
* Device state: non_compliant if any enabled check FAILs (informational severity excluded);
  otherwise unknown if any enabled check is UNKNOWN; otherwise compliant.
* Score = PASS / (enabled checks − NOT_APPLICABLE), as a percentage.
* Evidence is endpoint-reported (see SECURITY.md: a compromised endpoint can lie)."""
from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import utcnow
from app.models import ComplianceCheckSetting, ComplianceEvaluation, ComplianceResult, Device, DeviceEvent, DeviceInventory
from app.services import notifications

PASS, FAIL, UNKNOWN, NA = "PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"
SEVERITIES = ("critical", "high", "medium", "low", "informational")


@dataclass(frozen=True)
class Check:
    key: str
    name: str
    severity: str
    description: str
    remediation: str
    evaluate: Callable[[dict, dict], tuple[str, dict]]


def _sec(inv: dict, name: str) -> dict:
    return (inv.get("security") or {}).get(name) or {"state": "unknown", "data": {}, "detail": "not reported"}


def _state_check(name: str, *, good: str = "enabled") -> Callable[[dict, dict], tuple[str, dict]]:
    def ev(inv: dict, _os: dict) -> tuple[str, dict]:
        c = _sec(inv, name)
        st = c.get("state")
        evidence = {"reported_state": st, "detail": c.get("detail"), **(c.get("data") or {})}
        if st == "not_applicable":
            return NA, evidence
        if st == "unknown" or st is None:
            return UNKNOWN, evidence
        return (PASS if st == good else FAIL), evidence
    return ev


def _defender(inv: dict, _os: dict) -> tuple[str, dict]:
    c = _sec(inv, "defender")
    rtp = (c.get("data") or {}).get("real_time_protection")
    ev = {"reported_state": c.get("state"), **(c.get("data") or {})}
    if rtp is True:
        return PASS, ev
    if rtp is False:
        return FAIL, ev
    return UNKNOWN, ev


def _updates(max_days: int) -> Callable[[dict, dict], tuple[str, dict]]:
    def ev(inv: dict, _os: dict) -> tuple[str, dict]:
        c = _sec(inv, "windows_update")
        data = c.get("data") or {}
        days = data.get("days_since_last_update")
        evidence = {"threshold_days": max_days, **data, "detail": c.get("detail")}
        if not isinstance(days, int):
            return UNKNOWN, evidence
        return (PASS if days <= max_days else FAIL), evidence
    return ev


def _lockout(inv: dict, _os: dict) -> tuple[str, dict]:
    c = _sec(inv, "account_policy")
    data = c.get("data") or {}
    thr = data.get("lockout_threshold")
    if not isinstance(thr, int):
        return UNKNOWN, {"detail": c.get("detail"), **data}
    return (PASS if 0 < thr <= 50 else FAIL), data


def _rdp(inv: dict, _os: dict) -> tuple[str, dict]:
    c = _sec(inv, "remote_desktop")
    data = c.get("data") or {}
    st = c.get("state")
    if st == "disabled":
        return PASS, {"remote_desktop": "disabled"}
    if st == "enabled":
        nla = data.get("nla_required")
        if nla is True:
            return PASS, {"remote_desktop": "enabled", "nla_required": True, "note": "enabled with NLA — confirm business need"}
        if nla is False:
            return FAIL, {"remote_desktop": "enabled", "nla_required": False}
    return UNKNOWN, {"reported_state": st, **data}


def _credential_guard(inv: dict, os: dict) -> tuple[str, dict]:
    edition = (os.get("edition") or "").lower()
    c = _sec(inv, "credential_guard")
    ev = {"edition": os.get("edition"), "reported_state": c.get("state"), **(c.get("data") or {})}
    if c.get("state") == "enabled":
        return PASS, ev
    if edition and not any(e in edition for e in ("enterprise", "education", "server")):
        return NA, {**ev, "reason": "Credential Guard requires Enterprise/Education edition"}
    if c.get("state") == "disabled":
        return FAIL, ev
    return UNKNOWN, ev


def _audit_policy(inv: dict, _os: dict) -> tuple[str, dict]:
    c = _sec(inv, "audit_policy")
    data = c.get("data") or {}
    if c.get("state") in ("unknown", None):
        return UNKNOWN, {"detail": c.get("detail")}
    required = ("logon", "account_lockout", "user_account_management", "security_group_management")
    missing = [k for k in required if data.get(k) not in ("success_and_failure", "success", "failure")]
    return (FAIL if missing else PASS), {**data, "missing": missing}


def catalogue(max_update_days: int = 35) -> list[Check]:
    return [
        Check("firewall_enabled", "Windows Firewall enabled", "critical",
              "All firewall profiles (domain, private, public) are enabled.",
              "Assign a Firewall policy, or run `Set-NetFirewallProfile -All -Enabled True` as administrator.",
              _state_check("firewall")),
        Check("bitlocker_enabled", "BitLocker on system drive", "high",
              "The operating-system volume is protected by BitLocker.",
              "Escrow a recovery key, then enable BitLocker (Settings → Device encryption, or `manage-bde -on C:`). "
              "Windows Home only supports device encryption on eligible hardware.", _state_check("bitlocker")),
        Check("defender_realtime", "Defender real-time protection", "critical",
              "Microsoft Defender real-time protection is on.",
              "Turn on real-time protection (Windows Security → Virus & threat protection) or assign an Antivirus policy. "
              "If a third-party antivirus is in use, document it and disable this check.", _defender),
        Check("secure_boot", "Secure Boot enabled", "medium", "UEFI Secure Boot is enabled.",
              "Enable Secure Boot in UEFI firmware settings (requires UEFI boot mode and a GPT system disk).",
              _state_check("secure_boot")),
        Check("updates_current", "Security updates current", "high",
              f"A Windows update was installed within the last {max_update_days} days.",
              "Run Windows Update, install pending updates and restart; assign a Windows Update policy.",
              _updates(max_update_days)),
        Check("account_lockout", "Account lockout policy configured", "medium",
              "Local accounts lock after a bounded number of failed sign-ins.",
              "Assign a Password policy, or run `net accounts /lockoutthreshold:5` as administrator.", _lockout),
        Check("screen_lock", "Screen lock enabled", "medium",
              "An inactivity lock with password on resume is configured.",
              "Assign a Screen Lock policy (inactivity limit ≤ 15 minutes).", _state_check("screen_lock")),
        Check("remote_desktop", "Remote Desktop reviewed", "high",
              "Remote Desktop is disabled, or enabled with Network Level Authentication.",
              "Disable Remote Desktop if unused; otherwise require NLA (System → Remote Desktop → Advanced).", _rdp),
        Check("smb1_disabled", "SMBv1 disabled", "high", "The obsolete SMBv1 server protocol is disabled.",
              "Run `Set-SmbServerConfiguration -EnableSMB1Protocol $false` and remove the SMB1 optional feature.",
              _state_check("smb1", good="disabled")),
        Check("guest_disabled", "Guest account disabled", "medium", "The built-in Guest account is disabled.",
              "Run `Disable-LocalUser -Name Guest` as administrator.", _state_check("guest_account", good="disabled")),
        Check("credential_guard", "Credential Guard running", "low",
              "Virtualisation-based Credential Guard protects LSA secrets (Enterprise/Education editions).",
              "Enable via Group Policy: Device Guard → Turn On Virtualization Based Security.", _credential_guard),
        Check("audit_policy", "Windows audit policy configured", "medium",
              "Logon, account lockout and account/group management events are audited.",
              "Run `auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable` (and the other required "
              "subcategories) as administrator.", _audit_policy),
    ]


CHECK_KEYS = [c.key for c in catalogue()]


def effective_checks(db: Session, org_id: uuid.UUID) -> list[tuple[Check, bool, str]]:
    overrides = {s.check_key: s for s in db.scalars(select(ComplianceCheckSetting)
                                                    .where(ComplianceCheckSetting.organization_id == org_id))}
    out = []
    for c in catalogue():
        o = overrides.get(c.key)
        out.append((c, o.enabled if o else True, o.severity if o else c.severity))
    return out


def evaluate(db: Session, device: Device, inv: DeviceInventory) -> ComplianceEvaluation:
    inv_dict = {"security": inv.security or {}}
    os_info = inv.os or {}
    counts = {PASS: 0, FAIL: 0, UNKNOWN: 0, NA: 0}
    blocking_fail = False
    collected: dict[str, tuple[str, dict]] = {}
    evaluation = ComplianceEvaluation(id=uuid.uuid4(), organization_id=device.organization_id, device_id=device.id,
                                      inventory_id=inv.id, evaluated_at=utcnow(), state="unknown", score=0,
                                      passed=0, failed=0, unknown=0, not_applicable=0)
    db.add(evaluation)
    for check, enabled, severity in effective_checks(db, device.organization_id):
        if not enabled:
            continue
        try:
            result, evidence = check.evaluate(inv_dict, os_info)
        except Exception as exc:  # a malformed report must never be treated as passing
            result, evidence = UNKNOWN, {"error": f"evaluation error: {exc.__class__.__name__}"}
        counts[result] += 1
        collected[check.key] = (result, evidence)
        if result == FAIL and severity != "informational":
            blocking_fail = True
        db.add(ComplianceResult(evaluation_id=evaluation.id, device_id=device.id, check_key=check.key, result=result,
                                severity=severity, evidence=_jsonable(evidence)))
    applicable = counts[PASS] + counts[FAIL] + counts[UNKNOWN]
    evaluation.passed, evaluation.failed = counts[PASS], counts[FAIL]
    evaluation.unknown, evaluation.not_applicable = counts[UNKNOWN], counts[NA]
    evaluation.score = round(100 * counts[PASS] / applicable) if applicable else 0
    evaluation.state = "non_compliant" if blocking_fail else "unknown" if counts[UNKNOWN] else "compliant"

    if device.compliance_state != evaluation.state:
        db.add(DeviceEvent(device_id=device.id, kind="compliance_changed",
                           details={"from": device.compliance_state, "to": evaluation.state, "score": evaluation.score}))
        if evaluation.state == "non_compliant":
            notifications.notify_users(
                db, device.organization_id,
                notifications.users_with_permission(db, device.organization_id, "compliance:read"),
                kind="device.non_compliant", severity="medium",
                title=f"Endpoint non-compliant: {device.hostname}",
                body=f"{counts[FAIL]} check(s) failing, score {evaluation.score}%.", link=f"/endpoints/{device.id}")
    device.compliance_state = evaluation.state
    from app.services import alerts
    alerts.on_compliance(db, device, collected)
    return evaluation


def _jsonable(d: dict) -> dict:
    return {k: (v if isinstance(v, (str, int, float, bool, type(None), list)) else str(v)) for k, v in d.items()}


def latest_evaluation(db: Session, device_id: uuid.UUID) -> ComplianceEvaluation | None:
    return db.scalar(select(ComplianceEvaluation).where(ComplianceEvaluation.device_id == device_id)
                     .order_by(ComplianceEvaluation.evaluated_at.desc()).limit(1))


def latest_evaluations(db: Session, device_ids: list[uuid.UUID]) -> dict[uuid.UUID, ComplianceEvaluation]:
    """Latest evaluation for many devices in one query (window function; PostgreSQL and SQLite 3.25+)."""
    if not device_ids:
        return {}
    rn = func.row_number().over(partition_by=ComplianceEvaluation.device_id,
                                order_by=ComplianceEvaluation.evaluated_at.desc()).label("rn")
    sq = select(ComplianceEvaluation.id, rn).where(ComplianceEvaluation.device_id.in_(device_ids)).subquery()
    rows = db.scalars(select(ComplianceEvaluation).join(sq, sq.c.id == ComplianceEvaluation.id).where(sq.c.rn == 1))
    return {e.device_id: e for e in rows}


def org_history(db: Session, org_id: uuid.UUID, days: int = 30, owner_admin_id: uuid.UUID | None = None) -> list[dict]:
    """Per day: last evaluation of each device that day → average score and state counts."""
    from app.models import Device
    start = utcnow() - timedelta(days=days - 1)
    start = datetime(start.year, start.month, start.day, tzinfo=start.tzinfo)
    q = (select(ComplianceEvaluation.device_id, ComplianceEvaluation.evaluated_at,
                ComplianceEvaluation.score, ComplianceEvaluation.state)
         .where(ComplianceEvaluation.organization_id == org_id, ComplianceEvaluation.evaluated_at >= start)
         .order_by(ComplianceEvaluation.evaluated_at))
    if owner_admin_id is not None:  # admin isolation
        q = q.join(Device, Device.id == ComplianceEvaluation.device_id).where(Device.owner_admin_id == owner_admin_id)
    rows = db.execute(q).all()
    per_day: dict[str, dict[uuid.UUID, tuple[int, str]]] = {}
    for dev, ts, score, state in rows:
        per_day.setdefault(ts.date().isoformat(), {})[dev] = (score, state)
    out = []
    for i in range(days):
        d = (start + timedelta(days=i)).date().isoformat()
        vals = per_day.get(d, {}).values()
        out.append({
            "date": d,
            "devices": len(vals),
            "average_score": round(sum(v[0] for v in vals) / len(vals)) if vals else None,
            "compliant": sum(1 for v in vals if v[1] == "compliant"),
            "non_compliant": sum(1 for v in vals if v[1] == "non_compliant"),
            "unknown": sum(1 for v in vals if v[1] == "unknown"),
        })
    return out
