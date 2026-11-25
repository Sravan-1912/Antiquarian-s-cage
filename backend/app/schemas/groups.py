from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import ORMModel
from app.schemas.remote import StepUp


class GroupCriteria(BaseModel):
    model_config = ConfigDict(extra="forbid")
    q: str | None = Field(default=None, max_length=100)
    status: Literal["active", "suspended", "revoked", "unenrolled"] | None = None
    connectivity: Literal["online", "offline", "never"] | None = None
    os: str | None = Field(default=None, max_length=64)
    compliance_state: Literal["compliant", "non_compliant", "unknown"] | None = None


class GroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=500)
    criteria: GroupCriteria = Field(default_factory=GroupCriteria)


class GroupUpdate(GroupCreate):
    pass


class GroupOut(ORMModel):
    id: uuid.UUID
    name: str
    description: str
    criteria: dict
    created_at: datetime
    updated_at: datetime
    member_count: int = 0


class GroupPreviewRequest(BaseModel):
    criteria: GroupCriteria = Field(default_factory=GroupCriteria)


class GroupMemberOut(BaseModel):
    id: uuid.UUID
    display_name: str
    hostname: str
    status: str
    os_name: str | None
    compliance_state: str
    connectivity: str
    online: bool


# ----------------------------------------------------------------------------------- bulk actions
class BulkScript(BaseModel):
    kind: Literal["script"]
    script_id: uuid.UUID
    reason: str = Field(min_length=3, max_length=500)


class BulkAction(BaseModel):
    kind: Literal["action"]
    command: Literal["device.inspect", "device.lock", "device.restart", "device.restart_cancel",
                     "device.isolate", "device.release"]
    parameters: dict = Field(default_factory=dict)
    reason: str = Field(min_length=3, max_length=500)
    step_up: StepUp | None = None


class BulkStatus(BaseModel):
    kind: Literal["status"]
    op: Literal["suspend", "reactivate"]
    reason: str = Field(min_length=3, max_length=500)


class BulkResultItem(BaseModel):
    device_id: uuid.UUID
    hostname: str
    ok: bool
    detail: str | None = None


class BulkResultOut(BaseModel):
    kind: str
    total: int
    dispatched: int
    skipped: int
    results: list[BulkResultItem]
