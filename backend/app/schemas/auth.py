from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.schemas.common import ORMModel

Name = Field(min_length=2, max_length=200)


def _strip(v: str) -> str:
    v = v.strip()
    if any(ord(c) < 32 for c in v):
        raise ValueError("control characters are not allowed")
    return v


Password = Field(min_length=1, max_length=200)


class RegisterRequest(BaseModel):
    organization_name: str = Name
    full_name: str = Name
    email: EmailStr
    password: str = Password

    _s = field_validator("organization_name", "full_name")(_strip)


class RegisterResponse(BaseModel):
    detail: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Password


class ChangePasswordRequest(BaseModel):
    current_password: str = Password
    new_password: str = Password


class RoleOut(ORMModel):
    key: str
    name: str


class MeResponse(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    organization_id: uuid.UUID
    organization_name: str
    roles: list[RoleOut]
    permissions: list[str]
    email_verified: bool
    last_login_at: datetime | None
    must_change_password: bool = False


class LoginResponse(BaseModel):
    mfa_required: bool = False
    # True when the account signed in with a temporary password and must set a new one before continuing.
    must_change_password: bool = False


class BootstrapStatus(BaseModel):
    needs_setup: bool


class SessionOut(ORMModel):
    id: uuid.UUID
    ip: str | None
    user_agent: str | None
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    current: bool = False


class AuthEventOut(ORMModel):
    id: uuid.UUID
    event_type: str
    success: bool
    reason: str | None
    ip: str | None
    user_agent: str | None
    email_attempted: str | None
    created_at: datetime
