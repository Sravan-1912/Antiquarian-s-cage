"""Security alert detection and workflow.

Alerts are *leads for an analyst*, not verdicts. Each carries a kind:
  configuration       — a security setting is not as required (e.g. firewall off). Not an attack.
  operational         — something stopped working (agent silent, deployments failing).
  suspicious_activity — a pattern worth investigating (failed sign-in bursts, unusual admin activity).
Titles state what was observed. Open alerts are de-duplicated by key (occurrence count increases instead of
creating noise); configuration/operational alerts resolve themselves when the condition clears.
"""
from __future__ import annotations

import uuid
from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utcnow
from app.models import (
    AlertEvent, AuditLog, AuthenticationEvent, Device, EndpointPolicy, PolicyAssignment, PolicyDeployment,
    SecurityAlert, User,
)
from app.services import notifications

OPEN = ("new", "triaging", "investigating")
SEVERITIES = ("critical", "high", "medium", "low", "informational")
NOTIFY_AT = {"critical", "high", "medium"}

RULES: dict[str, dict] = {
    "auth_failed_burst": {"name": "Multiple failed sign-ins", "kind": "suspicious_activity"},
    "auth_ip_spray": {"name": "Failed sign-ins across several accounts from one address", "kind": "suspicious_activity"},
    "auth_success_after_failures": {"name": "Successful sign-in after repeated failures", "kind": "suspicious_activity"},
    "firewall_disabled": {"name": "Firewall disabled", "kind": "configuration"},
    "antivirus_disabled": {"name": "Antivirus real-time protection off", "kind": "configuration"},
    "bitlocker_disabled": {"name": "BitLocker not protecting system drive", "kind": "configuration"},
    "usb_storage_connected": {"name": "USB storage connected", "kind": "suspicious_activity"},
    "agent_silent": {"name": "Endpoint agent stopped reporting", "kind": "operational"},
    "deployment_failures": {"name": "Repeated policy deployment failures", "kind": "operational"},
    "admin_activity_burst": {"name": "Unusual administrative activity", "kind": "suspicious_activity"},
    "authz_denied_burst": {"name": "Repeated permission denials", "kind": "suspicious_activity"},
    "remote_access_anomaly": {"name": "Suspicious remote access activity", "kind": "suspicious_activity"},
    "audit_integrity": {"name": "Audit log integrity check failed", "kind": "suspicious_activity"},
    "audit_anchor_failed": {"name": "Audit anchor not written externally", "kind": "operational"},
}


def raise_alert(db: Session, org_id: uuid.UUID, rule_key: str, *, title: str, description: str, severity: str,
                dedup_key: str, device_id: uuid.UUID | None = None, employee_id: uuid.UUID | None = None,
                subject_user_id: uuid.UUID | None = None, subject_label: str | None = None,
                evidence: dict | None = None, auto_resolvable: bool = False) -> SecurityAlert:
    now = utcnow()
    existing = db.scalar(select(SecurityAlert).where(SecurityAlert.organization_id == org_id,
                                                     SecurityAlert.dedup_key == dedup_key,
                                                     SecurityAlert.status.in_(OPEN)))
    if existing:
        existing.occurrences += 1
        existing.last_seen_at = now
        existing.evidence = {**(existing.evidence or {}), **(evidence or {})}
        escalated = SEVERITIES.index(severity) < SEVERITIES.index(existing.severity)
        if escalated:
            existing.severity = severity
        db.add(AlertEvent(alert_id=existing.id, kind="reoccurred", actor_label="detection",
                          details={"occurrences": existing.occurrences, **({"escalated_to": severity} if escalated else {})}))
        if escalated and severity in NOTIFY_AT:
            _notify(db, existing)
        return existing
    if device_id and employee_id is None:
        d = db.get(Device, device_id)
        employee_id = d.employee_id if d else None
    a = SecurityAlert(id=uuid.uuid4(), organization_id=org_id, rule_key=rule_key, kind=RULES[rule_key]["kind"],
                      title=title[:200], description=description, severity=severity, device_id=device_id,
                      employee_id=employee_id, subject_user_id=subject_user_id, subject_label=subject_label,
                      detected_at=now, last_seen_at=now, dedup_key=dedup_key[:200], evidence=evidence or {},
                      auto_resolvable=auto_resolvable)
    db.add(a)
    db.flush()
    db.add(AlertEvent(alert_id=a.id, kind="created", actor_label="detection", details={"rule": rule_key}))
    if severity in NOTIFY_AT:
        _notify(db, a)
    return a


def _notify(db: Session, a: SecurityAlert) -> None:
    kind = "alert.agent_silent" if a.rule_key == "agent_silent" else f"alert.{a.rule_key}"
    notifications.notify_users(db, a.organization_id, notifications.users_with_permission(db, a.organization_id, "alerts:read"),
                               kind=kind, severity=a.severity, title=a.title, body=a.description[:300],
                               link=f"/alerts/{a.id}")


def auto_resolve(db: Session, org_id: uuid.UUID, dedup_key: str, reason: str) -> None:
    for a in db.scalars(select(SecurityAlert).where(SecurityAlert.organization_id == org_id,
                                                    SecurityAlert.dedup_key == dedup_key,
                                                    SecurityAlert.status.in_(OPEN),
                                                    SecurityAlert.auto_resolvable.is_(True))):
        a.status, a.resolved_at = "resolved", utcnow()
        a.resolution_notes = f"Resolved automatically: {reason}"
        db.add(AlertEvent(alert_id=a.id, kind="auto_resolved", actor_label="detection", details={"reason": reason}))


# ------------------------------------------------------------------------------------------- authentication
def on_failed_login(db: Session, org_id: uuid.UUID, email: str, user: User | None, ip: str | None) -> None:
    since = utcnow() - timedelta(minutes=15)
    n = db.scalar(select(func.count()).select_from(AuthenticationEvent).where(
        AuthenticationEvent.organization_id == org_id, AuthenticationEvent.event_type == "login",
        AuthenticationEvent.success.is_(False), func.lower(AuthenticationEvent.email_attempted) == email.lower(),
        AuthenticationEvent.created_at >= since)) or 0
    if n >= 5:
        raise_alert(db, org_id, "auth_failed_burst", title=f"{n} failed sign-ins for {email} in 15 minutes",
                    description="Repeated failed password sign-ins for one account. This can be a forgotten password "
                                "or a password-guessing attempt; check the source addresses and with the user.",
                    severity="high" if n >= 10 else "medium", dedup_key=f"auth_failed:{email.lower()}",
                    subject_user_id=user.id if user else None, subject_label=email,
                    evidence={"failures_15m": n, "last_source_ip": ip})
    if ip:
        rows = db.execute(select(AuthenticationEvent.email_attempted).where(
            AuthenticationEvent.organization_id == org_id, AuthenticationEvent.event_type == "login",
            AuthenticationEvent.success.is_(False), AuthenticationEvent.ip == ip,
            AuthenticationEvent.created_at >= since)).scalars().all()
        accounts = {(r or "").lower() for r in rows}
        if len(rows) >= 10 and len(accounts) >= 3:
            raise_alert(db, org_id, "auth_ip_spray", title=f"Failed sign-ins for {len(accounts)} accounts from {ip}",
                        description="Many accounts failed to sign in from the same address within 15 minutes — a "
                                    "pattern consistent with password spraying. Consider blocking the address.",
                        severity="high", dedup_key=f"auth_spray:{ip}", subject_label=ip,
                        evidence={"failures_15m": len(rows), "accounts": sorted(accounts)[:20], "source_ip": ip})


def on_successful_login(db: Session, user: User, ip: str | None, method: str) -> None:
    since = utcnow() - timedelta(minutes=15)
    failures = db.scalar(select(func.count()).select_from(AuthenticationEvent).where(
        AuthenticationEvent.user_id == user.id, AuthenticationEvent.event_type == "login",
        AuthenticationEvent.success.is_(False), AuthenticationEvent.created_at >= since)) or 0
    if failures >= 3:
        raise_alert(db, user.organization_id, "auth_success_after_failures",
                    title=f"{user.email} signed in after {failures} failed attempts",
                    description="A successful sign-in followed several failures. Confirm with the user that it was "
                                "them; if not, reset the password and revoke sessions.",
                    severity="medium", dedup_key=f"auth_after_fail:{user.id}:{utcnow():%Y%m%d%H}",
                    subject_user_id=user.id, subject_label=user.email,
                    evidence={"failures_15m": failures, "source_ip": ip, "method": method})


# ------------------------------------------------------------------------------------------- endpoints
COMPLIANCE_RULES = {
    "firewall_enabled": ("firewall_disabled", "high", "Windows Firewall is off on at least one profile."),
    "defender_realtime": ("antivirus_disabled", "high", "Microsoft Defender real-time protection is off. If a "
                          "third-party antivirus is approved, disable this compliance check instead."),
    "bitlocker_enabled": ("bitlocker_disabled", "medium", "The system drive is not protected by BitLocker."),
}


def on_compliance(db: Session, device: Device, results: dict[str, tuple[str, dict]]) -> None:
    for check, (rule, severity, text) in COMPLIANCE_RULES.items():
        if check not in results:
            continue
        result, evidence = results[check]
        key = f"{rule}:{device.id}"
        if result == "FAIL":
            raise_alert(db, device.organization_id, rule, title=f"{RULES[rule]['name']} on {device.hostname}",
                        description=f"{text} This is a configuration finding reported by the endpoint, not "
                                    "evidence of compromise.", severity=severity, dedup_key=key, device_id=device.id,
                        subject_label=device.hostname, evidence=evidence, auto_resolvable=True)
        elif result == "PASS":
            auto_resolve(db, device.organization_id, key, "the endpoint now reports the setting as compliant")


def on_usb_connected(db: Session, device: Device, name: str) -> None:
    restricted = db.scalar(select(EndpointPolicy.configuration).join(
        PolicyAssignment, PolicyAssignment.policy_id == EndpointPolicy.id).where(
        PolicyAssignment.device_id == device.id, PolicyAssignment.revoked_at.is_(None),
        EndpointPolicy.category == "usb", EndpointPolicy.status == "active"))
    blocked = bool(restricted) and restricted.get("mode") in ("block_storage", "read_only")
    raise_alert(db, device.organization_id, "usb_storage_connected",
                title=f"USB storage connected to {device.hostname}" + (" despite restriction policy" if blocked else ""),
                description=("A USB mass-storage device was connected although a USB restriction policy is assigned. "
                             "Verify the policy is applied and whether the device is allowlisted.") if blocked else
                            "A USB mass-storage device was connected. No USB restriction policy is assigned.",
                severity="medium" if blocked else "informational",
                dedup_key=f"usb:{device.id}:{name}:{utcnow():%Y%m%d}", device_id=device.id,
                subject_label=device.hostname, evidence={"device": name, "restriction_policy": bool(blocked)})


def on_deployment_failure(db: Session, device: Device, policy_id: uuid.UUID) -> None:
    since = utcnow() - timedelta(hours=24)
    n = db.scalar(select(func.count()).select_from(PolicyDeployment).where(
        PolicyDeployment.device_id == device.id, PolicyDeployment.policy_id == policy_id,
        PolicyDeployment.status.in_(("failed", "needs_attention")), PolicyDeployment.updated_at >= since)) or 0
    if n >= 3:
        pol = db.get(EndpointPolicy, policy_id)
        raise_alert(db, device.organization_id, "deployment_failures",
                    title=f"{n} failed deployments of {pol.name if pol else 'a policy'} on {device.hostname}",
                    description="The same policy failed repeatedly on this endpoint in the last 24 hours. Check the "
                                "deployment details (e.g. broker not elevated, unsupported edition).",
                    severity="medium", dedup_key=f"deploy_fail:{device.id}:{policy_id}", device_id=device.id,
                    subject_label=device.hostname, evidence={"failures_24h": n, "policy_id": str(policy_id)},
                    auto_resolvable=True)


def on_deployment_success(db: Session, device: Device, policy_id: uuid.UUID) -> None:
    auto_resolve(db, device.organization_id, f"deploy_fail:{device.id}:{policy_id}", "a later deployment succeeded")


# ------------------------------------------------------------------------------------------- periodic sweep
DESTRUCTIVE = {"device.credentials_revoked", "device.unenrolled", "employee.offboarded", "user.disabled",
               "user.roles_changed", "policy.unassigned", "application.access_revoked", "remote.device.restart",
               "remote.account.disable", "remote.account.remove_admin", "org.remote_assistance_settings"}


def sweep(db: Session, now: datetime | None = None) -> int:
    now = now or utcnow()
    s = get_settings()
    raised = 0
    # Agent stopped reporting (and auto-resolve when it is back)
    silent_after = timedelta(minutes=s.agent_silence_alert_minutes)
    for d in db.scalars(select(Device).where(Device.status == "active", Device.last_heartbeat_at.is_not(None))):
        key = f"agent_silent:{d.id}"
        if now - d.last_heartbeat_at > silent_after:
            raise_alert(db, d.organization_id, "agent_silent", title=f"{d.hostname} stopped reporting",
                        description=f"No authenticated heartbeat for over {s.agent_silence_alert_minutes} minutes. The "
                                    "device may be off or offline, or the agent may have been stopped or removed.",
                        severity="medium", dedup_key=key, device_id=d.id, subject_label=d.hostname,
                        evidence={"last_heartbeat_at": d.last_heartbeat_at.isoformat()}, auto_resolvable=True)
            raised += 1
        else:
            auto_resolve(db, d.organization_id, key, "the agent is reporting again")

    window = now - timedelta(minutes=10)
    hour = f"{now:%Y%m%d%H}"
    rows = db.execute(select(AuditLog.organization_id, AuditLog.actor_user_id, AuditLog.actor_label, AuditLog.action,
                             AuditLog.result, AuditLog.target_id).where(AuditLog.created_at >= window,
                                                                       AuditLog.actor_type == "user")).all()
    destructive = Counter((r.organization_id, r.actor_user_id, r.actor_label) for r in rows if r.action in DESTRUCTIVE)
    for (org, uid, label), n in destructive.items():
        if n >= 5:
            raise_alert(db, org, "admin_activity_burst", title=f"{label} performed {n} high-impact actions in 10 minutes",
                        description="An unusually high rate of revocations, offboardings, role changes or remote "
                                    "actions by one administrator. Confirm it was planned work.",
                        severity="high", dedup_key=f"admin_burst:{uid}:{hour}", subject_user_id=uid,
                        subject_label=label, evidence={"actions_10m": n})
            raised += 1
    denied = Counter((r.organization_id, r.actor_user_id, r.actor_label) for r in rows if r.action == "authz.denied")
    for (org, uid, label), n in denied.items():
        if n >= 10:
            raise_alert(db, org, "authz_denied_burst", title=f"{n} permission denials for {label} in 10 minutes",
                        description="Repeated attempts to use functions outside the account's role — possibly probing.",
                        severity="medium", dedup_key=f"authz_denied:{uid}:{hour}", subject_user_id=uid,
                        subject_label=label, evidence={"denials_10m": n})
            raised += 1
    reauth = Counter((r.organization_id, r.actor_user_id, r.actor_label) for r in rows if r.action == "remote.reauth_failed")
    for (org, uid, label), n in reauth.items():
        if n >= 3:
            raise_alert(db, org, "remote_access_anomaly", title=f"{label} failed password confirmation {n} times for remote actions",
                        description="Sensitive remote actions were attempted with wrong password confirmations — the "
                                    "session may be used by someone else.", severity="high",
                        dedup_key=f"remote_reauth:{uid}:{hour}", subject_user_id=uid, subject_label=label,
                        evidence={"failures_10m": n})
            raised += 1
    hour_ago = now - timedelta(hours=1)
    remote_rows = db.execute(select(AuditLog.organization_id, AuditLog.target_id).where(
        AuditLog.created_at >= hour_ago, AuditLog.action.in_(("remote.session_denied", "remote.session_failed")))).all()
    for (org, target), n in Counter(remote_rows).items():
        if n >= 2 and target:
            d = db.get(Device, uuid.UUID(target))
            raise_alert(db, org, "remote_access_anomaly",
                        title=f"{n} refused remote-assistance requests on {d.hostname if d else target}",
                        description="Several remote-assistance requests to this endpoint were declined or failed within "
                                    "an hour. Check that the requests were legitimate.", severity="medium",
                        dedup_key=f"remote_denied:{target}:{hour}", device_id=d.id if d else None,
                        subject_label=d.hostname if d else None, evidence={"refused_1h": n})
            raised += 1
    return raised
