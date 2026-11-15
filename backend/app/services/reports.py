"""Reports built from live database data, exported as CSV or PDF.

Every report declares the permissions it needs beyond `reports:export`; exports are audited with row counts."""
from __future__ import annotations

import csv
import io
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import utcnow
from app.models import (
    Application, ApplicationAssignment, AuditLog, AuthenticationEvent, Device, Employee, EndpointPolicy,
    PolicyDeployment, SecurityAlert, User,
)
from app.services import compliance, devices


@dataclass
class Report:
    key: str
    title: str
    description: str
    permissions: tuple[str, ...]
    dated: bool  # whether the from/to range applies
    build: Callable[[Session, uuid.UUID, datetime, datetime], tuple[list[str], list[list]]]


def _ts(v: datetime | None) -> str:
    return v.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M") if v else ""


def _dev_own(owner):
    from app.models import Device
    return (Device.owner_admin_id == owner,) if owner is not None else ()


def _emp_own(owner):
    from app.models import Employee
    return (Employee.owner_admin_id == owner,) if owner is not None else ()


def _tenant_uids(db, org, owner):
    if owner is None:
        return None
    from sqlalchemy import or_ as _or
    return list(db.scalars(select(User.id).where(User.organization_id == org, _or(User.owner_admin_id == owner, User.id == owner))))


def _inventory(db, org, start=None, end=None, owner=None):
    cols = ["Hostname", "Status", "Connectivity", "Assigned to", "OS", "Build", "Manufacturer", "Model", "Serial",
            "Agent", "Enrolled", "Last heartbeat", "Last seen IP"]
    rows = []
    names = dict(db.execute(select(Employee.id, Employee.full_name).where(Employee.organization_id == org)).all())
    for d in db.scalars(select(Device).where(Device.organization_id == org, *_dev_own(owner)).order_by(Device.hostname)):
        rows.append([d.hostname, d.status, devices.connectivity(d), names.get(d.employee_id, ""), d.os_name, d.os_build,
                     d.manufacturer, d.model, d.serial_number, d.agent_version, _ts(d.enrolled_at),
                     _ts(d.last_heartbeat_at), d.last_seen_ip])
    return cols, rows


def _compliance(db, org, start=None, end=None, owner=None):
    cols = ["Hostname", "State", "Score %", "Failed", "Unknown", "N/A", "Failing checks", "Evaluated"]
    from app.models import ComplianceResult
    rows = []
    devs = db.scalars(select(Device).where(Device.organization_id == org, Device.status.in_(("active", "suspended")), *_dev_own(owner))
                      .order_by(Device.hostname)).all()
    latest = compliance.latest_evaluations(db, [d.id for d in devs])
    fails: dict = {}
    if latest:
        for ev_id, key in db.execute(select(ComplianceResult.evaluation_id, ComplianceResult.check_key).where(
                ComplianceResult.evaluation_id.in_([e.id for e in latest.values()]), ComplianceResult.result == "FAIL")
                .order_by(ComplianceResult.check_key)):
            fails.setdefault(ev_id, []).append(key)
    for d in devs:
        e = latest.get(d.id)
        failing = ", ".join(fails.get(e.id, [])) if e else ""
        rows.append([d.hostname, d.compliance_state, e.score if e else "", e.failed if e else "", e.unknown if e else "",
                     e.not_applicable if e else "", failing, _ts(e.evaluated_at) if e else "never"])
    return cols, rows


def _deployments(db, org, start=None, end=None, owner=None):
    cols = ["Updated", "Policy", "Version", "Endpoint", "Action", "Status", "Detail"]
    q = (select(PolicyDeployment, EndpointPolicy, Device).join(EndpointPolicy, EndpointPolicy.id == PolicyDeployment.policy_id)
         .join(Device, Device.id == PolicyDeployment.device_id)
         .where(EndpointPolicy.organization_id == org, PolicyDeployment.updated_at >= start, PolicyDeployment.updated_at < end,
                *_dev_own(owner))
         .order_by(PolicyDeployment.updated_at.desc()))
    return cols, [[_ts(x.updated_at), p.name, x.policy_version, d.hostname, x.action, x.status, (x.detail or "")[:200]]
                  for x, p, d in db.execute(q)]


def _auth(db, org, start=None, end=None, owner=None):
    cols = ["Time", "Event", "Account", "Result", "Reason", "Application", "IP", "Client"]
    apps = {a.id: a.name for a in db.scalars(select(Application).where(Application.organization_id == org))}
    uids = _tenant_uids(db, org, owner)
    q = (select(AuthenticationEvent).where(AuthenticationEvent.organization_id == org,
                                           AuthenticationEvent.created_at >= start, AuthenticationEvent.created_at < end,
                                           *((AuthenticationEvent.user_id.in_(uids),) if uids is not None else ()))
         .order_by(AuthenticationEvent.created_at.desc()).limit(20000))
    return cols, [[_ts(e.created_at), e.event_type, e.email_attempted, "success" if e.success else "failure", e.reason,
                   apps.get(e.application_id, ""), e.ip, (e.user_agent or "")[:60]] for e in db.scalars(q)]


def _audit(db, org, start=None, end=None, owner=None):
    cols = ["Seq", "Time", "Actor", "Action", "Target", "Result", "Source IP", "Hash"]
    q = (select(AuditLog).where(AuditLog.organization_id == org, AuditLog.created_at >= start, AuditLog.created_at < end)
         .order_by(AuditLog.seq).limit(50000))
    return cols, [[a.seq, _ts(a.created_at), a.actor_label, a.action, a.target_label, a.result, a.source_ip, a.hash[:16]]
                  for a in db.scalars(q)]


def _access(db, org, start=None, end=None, owner=None):
    cols = ["Employee", "Email", "Department", "Status", "Workspace account", "Application", "Granted", "Revoked"]
    rows = []
    user_status = dict(db.execute(select(User.id, User.status).where(User.organization_id == org)).all())
    by_emp: dict = {}
    for x, a in db.execute(select(ApplicationAssignment, Application).join(
            Application, Application.id == ApplicationAssignment.application_id)
            .where(Application.organization_id == org)):
        by_emp.setdefault(x.employee_id, []).append((x, a))
    for e in db.scalars(select(Employee).where(Employee.organization_id == org, *_emp_own(owner)).order_by(Employee.full_name)):
        u_status = user_status.get(e.user_id) if e.user_id else None
        grants = by_emp.get(e.id, [])
        base = [e.full_name, e.email, e.department, e.status, u_status or "none"]
        if not grants:
            rows.append(base + ["", "", ""])
        for x, a in grants:
            rows.append(base + [a.name, _ts(x.granted_at), _ts(x.revoked_at)])
    return cols, rows


def _alerts(db, org, start=None, end=None, owner=None):
    cols = ["Detected", "Severity", "Kind", "Title", "Status", "Occurrences", "Assigned to", "Resolved", "Notes"]
    aown = (SecurityAlert.owner_admin_id == owner,) if owner is not None else ()
    q = (select(SecurityAlert).where(SecurityAlert.organization_id == org, SecurityAlert.detected_at >= start,
                                     SecurityAlert.detected_at < end, *aown).order_by(SecurityAlert.detected_at.desc()))
    rows = []
    emails = dict(db.execute(select(User.id, User.email).where(User.organization_id == org)).all())
    for a in db.scalars(q):
        rows.append([_ts(a.detected_at), a.severity, a.kind, a.title, a.status, a.occurrences,
                     emails.get(a.assigned_to, "") if a.assigned_to else "",
                     _ts(a.resolved_at), (a.resolution_notes or "")[:200]])
    return cols, rows


def _health(db, org, start=None, end=None, owner=None):
    cols = ["Hostname", "Status", "Connectivity", "Last heartbeat", "Agent", "Compliance", "Open alerts",
            "Failed deployments (7d)"]
    since = utcnow() - timedelta(days=7)
    rows = []
    open_alerts = dict(db.execute(select(SecurityAlert.device_id, func.count()).where(
        SecurityAlert.organization_id == org, SecurityAlert.device_id.is_not(None),
        SecurityAlert.status.in_(("new", "triaging", "investigating"))).group_by(SecurityAlert.device_id)).all())
    failed = dict(db.execute(select(PolicyDeployment.device_id, func.count()).where(
        PolicyDeployment.status.in_(("failed", "needs_attention")), PolicyDeployment.updated_at >= since)
        .group_by(PolicyDeployment.device_id)).all())
    for d in db.scalars(select(Device).where(Device.organization_id == org, Device.status.in_(("active", "suspended")), *_dev_own(owner))
                        .order_by(Device.hostname)):
        alerts_n, fails = open_alerts.get(d.id, 0), failed.get(d.id, 0)
        rows.append([d.hostname, d.status, devices.connectivity(d), _ts(d.last_heartbeat_at), d.agent_version,
                     d.compliance_state, alerts_n, fails])
    return cols, rows


REPORTS: dict[str, Report] = {r.key: r for r in [
    Report("endpoint_inventory", "Endpoint inventory", "All enrolled endpoints with reported hardware and OS.", ("devices:read",), False, _inventory),
    Report("device_compliance", "Device compliance", "Latest compliance evaluation per managed endpoint.", ("compliance:read",), False, _compliance),
    Report("policy_deployments", "Security policy deployments", "Deployment outcomes in the period.", ("policies:read",), True, _deployments),
    Report("authentication_history", "Authentication history", "Console, passkey and SSO authentication events.", ("users:read",), True, _auth),
    Report("audit_history", "Administrative audit history", "Hash-chained audit records in the period.", ("audit:read",), True, _audit),
    Report("employee_access", "Employee access", "Employees, workspace accounts and application grants.", ("employees:read", "applications:read"), False, _access),
    Report("security_alerts", "Security alerts", "Alerts detected in the period and their handling.", ("alerts:read",), True, _alerts),
    Report("endpoint_health", "Endpoint health", "Connectivity, compliance, open alerts and recent failures.", ("devices:read",), False, _health),
]}


def _cell(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def to_csv(cols: list[str], rows: list[list]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([_cell(v) for v in r])
    return ("﻿" + buf.getvalue()).encode("utf-8")  # BOM so Excel opens UTF-8 correctly


def to_pdf(report: Report, cols: list[str], rows: list[list], *, org_name: str, generated_by: str,
           period: str | None) -> bytes:
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos

    def clean(v) -> str:  # core PDF fonts are Latin-1
        return ("" if v is None else str(v)).encode("latin-1", "replace").decode("latin-1")

    class PDF(FPDF):
        def header(self):
            self.set_font("Helvetica", "B", 13)
            self.cell(0, 8, clean(f"{report.title}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_font("Helvetica", "", 8)
            self.set_text_color(90, 90, 90)
            meta = f"Antiquarian's Cage - {org_name} - generated {utcnow():%Y-%m-%d %H:%M} UTC by {generated_by}"
            if period:
                meta += f" - period {period}"
            self.cell(0, 5, clean(meta), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_text_color(0, 0, 0)
            self.ln(2)

        def footer(self):
            self.set_y(-12)
            self.set_font("Helvetica", "", 7)
            self.set_text_color(120, 120, 120)
            self.cell(0, 6, clean(f"{len(rows)} rows - page {self.page_no()}/{{nb}} - generated from live data"),
                      align="C")

    pdf = PDF(orientation="L", unit="mm", format="A4")
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()
    pdf.set_font("Helvetica", "", 7.5)
    width = pdf.w - pdf.l_margin - pdf.r_margin
    from fpdf.fonts import FontFace

    heading = FontFace(emphasis="BOLD", fill_color=(232, 236, 233))
    with pdf.table(width=width, line_height=4.2, text_align="LEFT", first_row_as_headings=True,
                   headings_style=heading, borders_layout="HORIZONTAL_LINES") as t:
        row = t.row()
        for c in cols:
            row.cell(clean(c))
        for r in rows:
            row = t.row()
            for v in r:
                text = clean(v)
                row.cell(text if len(text) <= 120 else text[:117] + "...")
    if not rows:
        pdf.ln(4)
        pdf.cell(0, 6, "No records for the selected scope.")
    return bytes(pdf.output())
