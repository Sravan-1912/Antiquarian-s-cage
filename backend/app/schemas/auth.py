from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.schemas.common import ORMModel

Name = Field(min_length=2, max_length=200)
Password = Field(min_length=1, max_length=256)


def _strip(v: str) -> str:
    v = v.strip()
    if any(ord(c) < 32 for c in v):
        raise ValueError("control characters are not allowed")
    return v


class RegisterRequest(BaseModel):
    organization_name: str = Name
    full_name: str = Name
    email: EmailStr
    password: str = Password

    _s = field_validator("organization_name", "full_name")(_strip)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Password


class TokenRequest(BaseModel):
    token: str = Field(min_length=20, max_length=128)


class ResetPasswordRequest(TokenRequest):
    new_password: str = Password


class AcceptInviteRequest(TokenRequest):
    password: str = Password


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ChangePasswordRequest(BaseModel):
    current_password: str = Password
    new_password: str = Password


class MfaCode(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class MfaDisableRequest(MfaCode):
    password: str = Password


class MfaSetupResponse(BaseModel):
    secret: str
    otpauth_uri: str


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
    mfa_enabled: bool
    email_verified: bool
    last_login_at: datetime | None


class LoginResponse(BaseModel):
    mfa_required: bool


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
