from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel

Interpreter = Literal["powershell", "cmd", "bash"]


class ScriptCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=500)
    interpreter: Interpreter = "powershell"
    content: str = Field(min_length=1, max_length=65_536)
    timeout_seconds: int = Field(default=300, ge=5, le=3600)


class ScriptUpdate(ScriptCreate):
    pass


class ScriptOut(ORMModel):
    id: uuid.UUID
    name: str
    description: str
    interpreter: str
    content: str
    timeout_seconds: int
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class ScriptSummaryOut(ORMModel):
    """Library listing — omits the (potentially large) content."""
    id: uuid.UUID
    name: str
    description: str
    interpreter: str
    timeout_seconds: int
    created_at: datetime
    updated_at: datetime


class ScriptDeployRequest(BaseModel):
    device_ids: list[uuid.UUID] = Field(min_length=1, max_length=500)
    reason: str = Field(min_length=3, max_length=500)


class ScriptRunOut(ORMModel):
    id: uuid.UUID
    script_id: uuid.UUID
    device_id: uuid.UUID
    script_name: str
    status: str
    exit_code: int | None
    stdout: str
    stderr: str
    requested_by_label: str | None
    created_at: datetime
    finished_at: datetime | None
