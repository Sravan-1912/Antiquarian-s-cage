from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

from app.schemas.auth import RoleOut
from app.schemas.common import ORMModel


def _clean(v: str | None) -> str | None:
    if v is None:
        return v
    v = v.strip()
    if any(ord(c) < 32 for c in v):
        raise ValueError("control characters are not allowed")
    return v


# ------------------------------------------------------------------ administrators
class AdminUserOut(ORMModel):
    id: uuid.UUID
    email: str
    full_name: str
    status: str
    email_verified_at: datetime | None
    last_login_at: datetime | None
    locked_until: datetime | None
    created_at: datetime
    roles: list[RoleOut]


class InviteAdminRequest(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=200)
    role: Literal["super_admin", "admin", "security_analyst", "it_support"]

    _c = field_validator("full_name")(_clean)


class SetRolesRequest(BaseModel):
    roles: list[Literal["super_admin", "admin", "security_analyst", "it_support", "employee"]] = Field(min_length=1)


class RoleDetail(ORMModel):
    key: str
    name: str
    description: str
    permissions: list[str]


# ------------------------------------------------------------------ employees
EmployeeStatus = Literal["invited", "active", "suspended", "offboarded"]


class EmployeeBase(BaseModel):
    full_name: str = Field(min_length=2, max_length=200)
    email: EmailStr
    department: str = Field(min_length=1, max_length=100)
    job_title: str = Field(min_length=1, max_length=150)
    manager_id: uuid.UUID | None = None
    start_date: date | None = None

    _c = field_validator("full_name", "department", "job_title")(_clean)


class EmployeeCreate(EmployeeBase):
    employee_number: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9._-]+$")
    status: Literal["invited", "active"] = "active"


class EmployeeUpdate(BaseModel):
    """Mover workflow: any change to department / title / manager is recorded as a 'mover' event."""

    full_name: str | None = Field(default=None, min_length=2, max_length=200)
    email: EmailStr | None = None
    department: str | None = Field(default=None, min_length=1, max_length=100)
    job_title: str | None = Field(default=None, min_length=1, max_length=150)
    manager_id: uuid.UUID | None = None
    start_date: date | None = None

    _c = field_validator("full_name", "department", "job_title")(_clean)

    @model_validator(mode="after")
    def _not_empty(self):
        if not self.model_fields_set:
            raise ValueError("no fields to update")
        return self


class LifecycleRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)
    end_date: date | None = None

    _c = field_validator("reason")(_clean)


class EmployeeOut(ORMModel):
    id: uuid.UUID
    employee_number: str
    full_name: str
    email: str
    department: str
    job_title: str
    status: str
    enrollment_status: str
    manager_id: uuid.UUID | None
    start_date: date | None
    end_date: date | None
    user_id: uuid.UUID | None = None
    created_at: datetime
    updated_at: datetime


class EmployeeEventOut(ORMModel):
    id: uuid.UUID
    kind: str
    details: dict
    actor_id: uuid.UUID | None
    created_at: datetime


# ------------------------------------------------------------------ audit / notifications
class AuditOut(ORMModel):
    id: uuid.UUID
    seq: int
    actor_type: str
    actor_label: str
    action: str
    target_type: str | None
    target_id: str | None
    target_label: str | None
    source_ip: str | None
    result: str
    event_metadata: dict = Field(serialization_alias="metadata")
    created_at: datetime
    prev_hash: str
    hash: str


class AuditVerifyOut(BaseModel):
    valid: bool
    checked: int
    first_invalid_seq: int | None
    reason: str | None
    head_seq: int | None
    head_hash: str | None
    verified_at: datetime
    anchors: "AnchorReportOut | None" = None


class AnchorReportOut(BaseModel):
    valid: bool
    anchors_checked: int
    external_file: str
    external_anchors: int
    last_anchor_seq: int | None
    last_anchor_at: str | None
    problems: list[str]


class AuditAnchorOut(ORMModel):
    seq: int
    hash: str
    created_at: datetime
    key_id: str
    external_written: bool
    external_error: str | None


class NotificationOut(ORMModel):
    id: uuid.UUID
    kind: str
    severity: str
    title: str
    body: str
    link: str | None
    read_at: datetime | None
    created_at: datetime


class SearchHit(BaseModel):
    type: Literal["employee", "administrator", "endpoint", "page"]
    id: str
    title: str
    subtitle: str
    link: str
