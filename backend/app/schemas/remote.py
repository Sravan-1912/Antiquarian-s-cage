from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app.schemas.common import ORMModel

# Windows local account names: max 20 chars, no \ / [ ] : ; | = , + * ? < > " @
Username = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._\- ]{1,20}$", strip_whitespace=True)]


class _P(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NoParams(_P):
    pass


class RestartParams(_P):
    delay_seconds: int = Field(default=300, ge=60, le=3600)
    message: str = Field(default="Your administrator scheduled a restart. Save your work.", max_length=200)

    @field_validator("message")
    @classmethod
    def _printable(cls, v: str) -> str:
        if any(ord(c) < 32 for c in v) or '"' in v:
            raise ValueError("message must be printable and must not contain quotes")
        return v


class AccountParams(_P):
    username: Username


ACTION_SCHEMAS: dict[str, type[_P]] = {
    "device.inspect": NoParams, "device.lock": NoParams, "device.restart": RestartParams,
    "device.restart_cancel": NoParams, "device.shutdown": RestartParams, "device.logoff": NoParams,
    "account.disable": AccountParams, "account.enable": AccountParams, "account.remove_admin": AccountParams,
    # Network isolation (killswitch): server_host is injected server-side so the broker keeps the agent→backend
    # channel open (otherwise the endpoint could never be released).
    "device.isolate": NoParams, "device.release": NoParams,
}
# Actions that change the device's availability or accounts need the operator to re-enter their password.
SENSITIVE = {"device.restart", "device.shutdown", "device.logoff", "account.disable", "account.enable",
             "account.remove_admin", "device.isolate", "device.release"}

ActionName = Literal["device.inspect", "device.lock", "device.restart", "device.restart_cancel", "device.shutdown",
                     "device.logoff", "account.disable", "account.enable", "account.remove_admin",
                     "device.isolate", "device.release"]


class StepUp(BaseModel):
    """Re-entry of the signed-in admin's password, confirming a sensitive action."""
    password: str = Field(min_length=1, max_length=200)


class ActionRequest(BaseModel):
    command: ActionName
    parameters: dict = Field(default_factory=dict)
    reason: str = Field(min_length=3, max_length=500)
    step_up: StepUp | None = None


class ActionOut(ORMModel):
    id: uuid.UUID
    device_id: uuid.UUID
    command: str
    parameters: dict
    status: str
    issued_at: datetime
    expires_at: datetime
    delivered_at: datetime | None
    completed_at: datetime | None
    result: dict
    requested_by: uuid.UUID | None
    requested_by_label: str | None = None


class AssistRequest(BaseModel):
    reason: str = Field(min_length=5, max_length=500)
    max_minutes: int = Field(default=30, ge=5, le=120)
    step_up: StepUp | None = None


class RdpRequest(BaseModel):
    """Start an unattended Remote Desktop session. No consent and no password step-up (by design), but the endpoint
    always shows a visible 'Remote desktop active' banner for the whole session."""
    reason: str = Field(min_length=5, max_length=500)
    max_minutes: int = Field(default=30, ge=5, le=120)


class ShellRequest(BaseModel):
    """Open an interactive live-response shell. Arbitrary command execution (break-glass): RBAC-gated, the endpoint
    always shows a visible banner, and every command + output is written to the audit trail. `elevated` runs it as
    SYSTEM/root (needs devices:shell_elevated)."""
    reason: str = Field(min_length=5, max_length=500)
    max_minutes: int = Field(default=30, ge=5, le=120)
    elevated: bool = False


class ScreenRequest(BaseModel):
    """Start an unattended remote-screen session: the agent captures the screen and injects input over the relay (works
    on any Windows edition, incl. Home). No consent/step-up, but the endpoint always shows a visible banner."""
    reason: str = Field(min_length=5, max_length=500)
    max_minutes: int = Field(default=30, ge=5, le=120)


class TerminateRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


class SessionOut(ORMModel):
    id: uuid.UUID
    device_id: uuid.UUID
    device_name: str | None = None
    requested_by_label: str
    reason: str
    mode: str = "assist"
    connection: str | None = None
    require_consent: bool
    max_minutes: int
    status: str
    consent_decision: str | None
    consent_user: str | None
    consented_at: datetime | None
    started_at: datetime | None
    expires_at: datetime | None
    ended_at: datetime | None
    ended_by: str | None
    end_reason: str | None
    created_at: datetime


class AssistSettings(BaseModel):
    require_consent: bool = True
    max_session_minutes: int = Field(default=60, ge=5, le=120)
    allow_it_support: bool = True


class AgentSessionEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event: Literal["ended_by_user", "expired", "helper_failed", "terminated"]
    detail: Annotated[str, StringConstraints(max_length=500)] | None = None
