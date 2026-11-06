"""Policy configuration schemas — one strict model per category. The backend validates every configuration before
it can be saved or deployed; the agent validates the same constraints again before applying."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app.schemas.common import ORMModel

Category = Literal["firewall", "bitlocker", "usb", "antivirus", "screen_lock", "windows_update", "password"]


class _Cfg(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FirewallConfig(_Cfg):
    """Enable Windows Firewall on the selected profiles. Disabling the firewall is not a supported policy action."""
    profiles: list[Literal["domain", "private", "public"]] = Field(default=["domain", "private", "public"], min_length=1)
    enforce: bool = True  # False = report only


class BitLockerConfig(_Cfg):
    """Monitoring + requirement. The agent never starts encryption automatically: enabling BitLocker without a
    verified recovery-key escrow can lock users out. Non-encrypted system drives are reported as needing attention."""
    require_system_drive_encryption: bool = True
    allowed_methods: list[Literal["XtsAes128", "XtsAes256", "AesCbc128", "AesCbc256"]] = Field(
        default=["XtsAes128", "XtsAes256"], min_length=1)


DeviceId = Annotated[str, StringConstraints(pattern=r"^(USB|USBSTOR)\\[A-Za-z0-9_&\\.\-]{3,200}$")]


class USBConfig(_Cfg):
    mode: Literal["allow", "read_only", "block_storage"]
    # Hardware/instance IDs exempt from blocking (enforced through Windows Device Installation Restrictions).
    allowlist: list[DeviceId] = Field(default_factory=list, max_length=100)
    monitor_connections: bool = True


class AntivirusConfig(_Cfg):
    require_real_time_protection: bool = True
    max_signature_age_days: int = Field(default=3, ge=0, le=30)
    enforce: bool = True  # re-enable real-time protection / trigger signature update when allowed (Tamper Protection may block)


class ScreenLockConfig(_Cfg):
    inactivity_timeout_seconds: int = Field(ge=60, le=3600)
    require_password_on_resume: bool = True


class WindowsUpdateConfig(_Cfg):
    max_days_since_last_update: int = Field(default=35, ge=7, le=120)
    configure_automatic_updates: bool = True
    scheduled_install_day: int = Field(default=0, ge=0, le=7)  # 0 = every day
    scheduled_install_hour: int = Field(default=3, ge=0, le=23)


class PasswordConfig(_Cfg):
    min_length: int = Field(ge=8, le=14)  # Windows local policy maximum is 14 without relaxing legacy limits
    complexity_enabled: bool = True
    lockout_threshold: int = Field(ge=3, le=50)
    lockout_duration_minutes: int = Field(ge=5, le=1440)
    lockout_window_minutes: int = Field(ge=5, le=1440)

    @field_validator("lockout_window_minutes")
    @classmethod
    def _window(cls, v: int, info) -> int:
        dur = info.data.get("lockout_duration_minutes")
        if dur is not None and v > dur:
            raise ValueError("lockout window must not exceed lockout duration (Windows requirement)")
        return v


CONFIG_MODELS: dict[str, type[_Cfg]] = {
    "firewall": FirewallConfig, "bitlocker": BitLockerConfig, "usb": USBConfig, "antivirus": AntivirusConfig,
    "screen_lock": ScreenLockConfig, "windows_update": WindowsUpdateConfig, "password": PasswordConfig,
}


def validate_config(category: str, config: dict) -> dict:
    return CONFIG_MODELS[category].model_validate(config).model_dump(mode="json")


class PolicyCreate(BaseModel):
    name: str = Field(min_length=3, max_length=128)
    description: str = Field(default="", max_length=2000)
    category: Category
    configuration: dict


class PolicyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=3, max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    configuration: dict | None = None


class PolicyOut(ORMModel):
    id: uuid.UUID
    name: str
    description: str
    category: str
    configuration: dict
    version: int
    status: str
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    assigned_devices: int = 0
    deployment_summary: dict[str, int] = {}


class AssignRequest(BaseModel):
    device_ids: list[uuid.UUID] = Field(min_length=1, max_length=500)


class UnassignRequest(BaseModel):
    device_ids: list[uuid.UUID] = Field(min_length=1, max_length=500)
    rollback: bool = True


class DeploymentOut(ORMModel):
    id: uuid.UUID
    policy_id: uuid.UUID
    device_id: uuid.UUID
    device_name: str | None = None
    policy_name: str | None = None
    policy_version: int
    action: str
    status: str
    detail: str | None
    result: dict
    previous_state: dict
    command_job_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class AssignmentOut(ORMModel):
    id: uuid.UUID
    policy_id: uuid.UUID
    device_id: uuid.UUID
    device_name: str | None = None
    assigned_at: datetime
    revoked_at: datetime | None
    latest_status: str | None = None


# ----------------------------------------------------------------------------------------- agent job channel
class JobResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["succeeded", "failed", "needs_attention", "rejected"]
    detail: Annotated[str, StringConstraints(max_length=2000)] | None = None
    previous_state: dict = Field(default_factory=dict)
    current_state: dict = Field(default_factory=dict)


class ComplianceSettingUpdate(BaseModel):
    enabled: bool
    severity: Literal["critical", "high", "medium", "low", "informational"]
