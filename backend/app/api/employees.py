"""Employee identity management with joiner / mover / leaver workflows."""
from __future__ import annotations

import csv
import io
import uuid
from datetime import date
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, require_permission
from app.core.database import get_db
from app.core.database import utcnow
from app.models import ApplicationAssignment, Employee, EmployeeEvent, User, UserRole, WebAuthnCredential
from app.schemas.admin import EmployeeCreate, EmployeeEventOut, EmployeeOut, EmployeeUpdate, LifecycleRequest
from app.schemas.common import Page
from app.services import audit, auth, notifications

router = APIRouter(prefix="/employees", tags=["employees"])

SORTABLE = {"full_name": Employee.full_name, "department": Employee.department, "created_at": Employee.created_at,
            "employee_number": Employee.employee_number, "status": Employee.status}


def _get(db: Session, ctx: AuthContext, emp_id: uuid.UUID) -> Employee:
    e = db.get(Employee, emp_id)
    if e is None or e.organization_id != ctx.user.organization_id:
        raise HTTPException(404, "Employee not found")
    return e


def _email_taken(db: Session, org_id: uuid.UUID, email_addr: str, exclude: uuid.UUID | None = None) -> bool:
    q = select(Employee.id).where(Employee.organization_id == org_id, func.lower(Employee.email) == email_addr.lower())
    if exclude:
        q = q.where(Employee.id != exclude)
    return db.scalar(q) is not None


def _filtered(ctx: AuthContext, q: str | None, status: str | None, department: str | None):
    stmt = select(Employee).where(Employee.organization_id == ctx.user.organization_id)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(Employee.full_name).like(like), func.lower(Employee.email).like(like),
                              func.lower(Employee.employee_number).like(like)))
    if status:
        stmt = stmt.where(Employee.status == status)
    if department:
        stmt = stmt.where(Employee.department == department)
    return stmt


@router.get("", response_model=Page[EmployeeOut])
def list_employees(
    q: str | None = Query(None, max_length=100),
    status: Literal["invited", "active", "suspended", "offboarded"] | None = None,
    department: str | None = Query(None, max_length=100),
    sort: Literal["full_name", "department", "created_at", "employee_number", "status"] = "full_name",
    order: Literal["asc", "desc"] = "asc",
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    ctx: AuthContext = Depends(require_permission("employees:read")),
    db: Session = Depends(get_db),
):
    stmt = _filtered(ctx, q, status, department)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    col = SORTABLE[sort]
    rows = db.scalars(stmt.order_by(col.desc() if order == "desc" else col.asc(), Employee.id)
                      .offset((page - 1) * page_size).limit(page_size)).all()
    return Page(items=[EmployeeOut.model_validate(r) for r in rows], total=total, page=page, page_size=page_size)


@router.get("/departments", response_model=list[str])
def departments(ctx: AuthContext = Depends(require_permission("employees:read")), db: Session = Depends(get_db)):
    return db.scalars(select(Employee.department).where(Employee.organization_id == ctx.user.organization_id)
                      .distinct().order_by(Employee.department)).all()


@router.get("/export.csv")
def export_csv(
    q: str | None = Query(None, max_length=100),
    status: Literal["invited", "active", "suspended", "offboarded"] | None = None,
    department: str | None = Query(None, max_length=100),
    ctx: AuthContext = Depends(require_permission("employees:read", "reports:export")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(_filtered(ctx, q, status, department).order_by(Employee.full_name)).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["employee_number", "full_name", "email", "department", "job_title", "status", "enrollment_status",
                "start_date", "end_date"])
    for r in rows:
        # Prefix cells that spreadsheet apps would evaluate as formulas (CSV injection).
        w.writerow([_safe(v) for v in (r.employee_number, r.full_name, r.email, r.department, r.job_title,
                                       r.status, r.enrollment_status, r.start_date or "", r.end_date or "")])
    audit.record(db, ctx.user.organization_id, ctx.actor, "report.exported", target_type="report",
                 target_label="employees.csv", metadata={"rows": len(rows)})
    db.commit()
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="employees.csv"'})


def _safe(v: object) -> str:
    s = str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@router.post("", response_model=EmployeeOut, status_code=201)
def create_employee(body: EmployeeCreate, ctx: AuthContext = Depends(require_permission("employees:write")),
                    db: Session = Depends(get_db)):
    org_id = ctx.user.organization_id
    if _email_taken(db, org_id, str(body.email)):
        raise HTTPException(409, "An employee with this email already exists")
    if db.scalar(select(Employee.id).where(Employee.organization_id == org_id,
                                           Employee.employee_number == body.employee_number)):
        raise HTTPException(409, "Employee ID is already in use")
    if body.manager_id:
        _get(db, ctx, body.manager_id)
    emp = Employee(organization_id=org_id, **body.model_dump(exclude={"email"}), email=str(body.email).lower())
    db.add(emp)
    db.flush()
    db.add(EmployeeEvent(employee_id=emp.id, kind="joiner", actor_id=ctx.user.id,
                         details={"department": emp.department, "job_title": emp.job_title, "status": emp.status}))
    audit.record(db, org_id, ctx.actor, "employee.created", target_type="employee", target_id=emp.id,
                 target_label=emp.email, metadata={"employee_number": emp.employee_number,
                                                   "department": emp.department})
    db.commit()
    return emp


@router.get("/{emp_id}", response_model=EmployeeOut)
def get_employee(emp_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("employees:read")),
                 db: Session = Depends(get_db)):
    return _get(db, ctx, emp_id)


@router.get("/{emp_id}/events", response_model=list[EmployeeEventOut])
def employee_events(emp_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("employees:read")),
                    db: Session = Depends(get_db)):
    _get(db, ctx, emp_id)
    return db.scalars(select(EmployeeEvent).where(EmployeeEvent.employee_id == emp_id)
                      .order_by(EmployeeEvent.created_at.desc())).all()


@router.patch("/{emp_id}", response_model=EmployeeOut)
def update_employee(emp_id: uuid.UUID, body: EmployeeUpdate,
                    ctx: AuthContext = Depends(require_permission("employees:write")), db: Session = Depends(get_db)):
    emp = _get(db, ctx, emp_id)
    if emp.status == "offboarded":
        raise HTTPException(409, "Offboarded employees cannot be modified")
    changes = body.model_dump(exclude_unset=True)
    if "email" in changes:
        changes["email"] = str(changes["email"]).lower()
        if _email_taken(db, emp.organization_id, changes["email"], exclude=emp.id):
            raise HTTPException(409, "An employee with this email already exists")
    if changes.get("manager_id"):
        if changes["manager_id"] == emp.id:
            raise HTTPException(422, "An employee cannot be their own manager")
        _get(db, ctx, changes["manager_id"])
    diff = {k: {"from": str(getattr(emp, k)) if getattr(emp, k) is not None else None,
                "to": str(v) if v is not None else None}
            for k, v in changes.items() if getattr(emp, k) != v}
    if not diff:
        return emp
    for k, v in changes.items():
        setattr(emp, k, v)
    is_mover = bool({"department", "job_title", "manager_id"} & diff.keys())
    db.add(EmployeeEvent(employee_id=emp.id, kind="mover" if is_mover else "update", actor_id=ctx.user.id,
                         details=diff))
    audit.record(db, emp.organization_id, ctx.actor, "employee.moved" if is_mover else "employee.updated",
                 target_type="employee", target_id=emp.id, target_label=emp.email, metadata={"changes": diff})
    db.commit()
    return emp


def _transition(db: Session, ctx: AuthContext, emp: Employee, *, allowed_from: set[str], to: str, kind: str,
                action: str, reason: str, end_date: date | None = None) -> Employee:
    if emp.status not in allowed_from:
        raise HTTPException(409, f"Cannot {kind} an employee whose status is '{emp.status}'")
    before = emp.status
    emp.status = to
    if end_date:
        emp.end_date = end_date
    revoked = 0
    details: dict = {}
    user = db.get(User, emp.user_id) if emp.user_id else None
    if to in ("suspended", "offboarded") and user:
        revoked = auth.revoke_user_sessions(db, user.id, f"employee_{to}")
        if user.status == "active":
            user.status = "disabled"  # portal sign-in and SSO stop immediately
            details["portal_account"] = "disabled"
    if to == "active" and user and user.status == "disabled":
        user.status = "active"
        details["portal_account"] = "re-enabled"
    if to == "offboarded":
        # Leaver: remove every application grant and passkey, not just the sessions.
        now = utcnow()
        apps = db.scalars(select(ApplicationAssignment).where(ApplicationAssignment.employee_id == emp.id,
                                                              ApplicationAssignment.revoked_at.is_(None))).all()
        for x in apps:
            x.revoked_at, x.revoked_by, x.revoke_reason = now, ctx.user.id, "leaver"
        details["application_access_revoked"] = len(apps)
        if user:
            creds = db.scalars(select(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id,
                                                                WebAuthnCredential.revoked_at.is_(None))).all()
            for c in creds:
                c.revoked_at, c.revoked_by = now, ctx.user.id
            details["passkeys_revoked"] = len(creds)
    details = {"from": before, "to": to, "reason": reason, "sessions_revoked": revoked, **details}
    db.add(EmployeeEvent(employee_id=emp.id, kind=kind, actor_id=ctx.user.id, details=details))
    audit.record(db, emp.organization_id, ctx.actor, action, target_type="employee", target_id=emp.id,
                 target_label=emp.email, metadata=details)
    return emp


@router.post("/{emp_id}/suspend", response_model=EmployeeOut)
def suspend(emp_id: uuid.UUID, body: LifecycleRequest,
            ctx: AuthContext = Depends(require_permission("employees:lifecycle")), db: Session = Depends(get_db)):
    emp = _transition(db, ctx, _get(db, ctx, emp_id), allowed_from={"active", "invited"}, to="suspended",
                      kind="suspend", action="employee.suspended", reason=body.reason)
    db.commit()
    return emp


@router.post("/{emp_id}/reactivate", response_model=EmployeeOut)
def reactivate(emp_id: uuid.UUID, body: LifecycleRequest,
               ctx: AuthContext = Depends(require_permission("employees:lifecycle")), db: Session = Depends(get_db)):
    emp = _transition(db, ctx, _get(db, ctx, emp_id), allowed_from={"suspended"}, to="active",
                      kind="reactivate", action="employee.reactivated", reason=body.reason)
    db.commit()
    return emp


@router.post("/{emp_id}/offboard", response_model=EmployeeOut)
def offboard(emp_id: uuid.UUID, body: LifecycleRequest,
             ctx: AuthContext = Depends(require_permission("employees:lifecycle")), db: Session = Depends(get_db)):
    """Leaver workflow. Access removal for devices and applications is extended in Phases 2 and 5."""
    emp = _transition(db, ctx, _get(db, ctx, emp_id), allowed_from={"active", "invited", "suspended"},
                      to="offboarded", kind="leaver", action="employee.offboarded", reason=body.reason,
                      end_date=body.end_date or date.today())
    notifications.notify_users(
        db, emp.organization_id, notifications.users_with_permission(db, emp.organization_id, "employees:lifecycle"),
        kind="employee.offboarded", severity="medium", title=f"Employee offboarded: {emp.full_name}",
        body=f"{ctx.user.full_name} offboarded {emp.full_name} ({emp.department}). Reason: {body.reason}",
        link=f"/employees/{emp.id}",
    )
    db.commit()
    return emp


# --------------------------------------------------------------------------------------------- portal accounts
@router.post("/{emp_id}/portal-access", response_model=EmployeeOut)
def grant_portal_access(emp_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("employees:lifecycle")),
                        db: Session = Depends(get_db)):
    """Creates the employee's own sign-in (role: Employee) and emails a single-use invitation."""
    from app.services import email, rbac
    from app.services.email import EmailDeliveryError

    emp = _get(db, ctx, emp_id)
    if emp.status != "active":
        raise HTTPException(409, "Only active employees can be given portal access")
    if emp.user_id:
        raise HTTPException(409, "This employee already has a portal account")
    if auth.find_user_by_email(db, emp.organization_id, emp.email):
        raise HTTPException(409, "An account with this email already exists (administrator accounts cannot be reused)")
    user = User(organization_id=emp.organization_id, email=emp.email.lower(), full_name=emp.full_name,
                password_hash=None, status="pending")
    db.add(user)
    db.flush()
    role = rbac.get_role(db, "employee")
    db.add(UserRole(user_id=user.id, role_id=role.id, granted_by=ctx.user.id))
    emp.user_id = user.id
    raw = auth.issue_invite(db, user)
    db.add(EmployeeEvent(employee_id=emp.id, kind="update", actor_id=ctx.user.id, details={"portal_access": {"from": None, "to": "invited"}}))
    audit.record(db, emp.organization_id, ctx.actor, "employee.portal_invited", target_type="employee",
                 target_id=emp.id, target_label=emp.email)
    db.commit()
    try:
        email.send_email(user.email, "Your Antiquarian's Cage account",
                         f"Hello {emp.full_name},\n\nActivate your workspace account (devices, applications, "
                         f"passkeys):\n{email.link('/accept-invite', raw)}")
    except EmailDeliveryError:
        raise HTTPException(502, "Account created, but the invitation email could not be sent")
    return emp


@router.delete("/{emp_id}/portal-access", response_model=EmployeeOut)
def revoke_portal_access(emp_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("employees:lifecycle")),
                         db: Session = Depends(get_db)):
    emp = _get(db, ctx, emp_id)
    user = db.get(User, emp.user_id) if emp.user_id else None
    if user is None:
        raise HTTPException(404, "No portal account")
    user.status = "disabled"
    n = auth.revoke_user_sessions(db, user.id, "portal_access_revoked")
    audit.record(db, emp.organization_id, ctx.actor, "employee.portal_revoked", target_type="employee",
                 target_id=emp.id, target_label=emp.email, metadata={"sessions_revoked": n})
    db.commit()
    return emp
