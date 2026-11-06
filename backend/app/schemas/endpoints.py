"""Schemas for the agent channel and device administration.

Agent payloads are untrusted: every field is length- and count-limited and stored as *reported* data."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app.schemas.common import ORMModel

Short = Annotated[str, StringConstraints(max_length=128, strip_whitespace=True)]
Tiny = Annotated[str, StringConstraints(max_length=64, strip_whitespace=True)]
HOSTNAME_RE = r"^[A-Za-z0-9][A-Za-z0-9.\-_]{0,62}$"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------------------------- agent
class OSInfo(_Strict):
    name: Short | None = None
    version: Tiny | None = None
    build: Tiny | None = None
    edition: Short | None = None
    architecture: Tiny | None = None
    install_date: Tiny | None = None
    last_boot: Tiny | None = None


class EnrollRequest(_Strict):
    token: str = Field(min_length=10, max_length=64)
    csr_pem: str = Field(min_length=100, max_length=4096)
    hostname: str = Field(pattern=HOSTNAME_RE)
    agent_version: Tiny
    os: OSInfo | None = None


class EnrollResponse(BaseModel):
    device_id: uuid.UUID
    certificate_pem: str
    ca_certificate_pem: str
    heartbeat_interval_seconds: int
    inventory_interval_seconds: int
    command_key_id: str
    command_public_key: str  # Ed25519, base64 — the agent pins this to verify signed commands


class HeartbeatRequest(_Strict):
    agent_version: Tiny
    uptime_seconds: int | None = Field(default=None, ge=0, le=10 * 365 * 86400)
    logged_in_user: Short | None = None


class HeartbeatResponse(BaseModel):
    status: str
    heartbeat_interval_seconds: int
    inventory_interval_seconds: int
    certificate_renewal_due: bool
    server_time: datetime
    jobs_pending: bool = False


class CPUInfo(_Strict):
    name: Short | None = None
    manufacturer: Short | None = None
    physical_cores: int | None = Field(default=None, ge=0, le=4096)
    logical_processors: int | None = Field(default=None, ge=0, le=8192)
    max_clock_mhz: int | None = Field(default=None, ge=0, le=100_000)


class DiskInfo(_Strict):
    device: Tiny
    mountpoint: Tiny
    filesystem: Tiny | None = None
    total_bytes: int = Field(ge=0)
    used_bytes: int = Field(ge=0)
    free_bytes: int = Field(ge=0)


class NetInterface(_Strict):
    name: Short
    mac_address: str | None = Field(default=None, pattern=r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
    ipv4: list[Tiny] = Field(default_factory=list, max_length=16)
    ipv6: list[Tiny] = Field(default_factory=list, max_length=16)
    is_up: bool | None = None
    speed_mbps: int | None = Field(default=None, ge=0, le=1_000_000)


class HardwareInfo(_Strict):
    manufacturer: Short | None = None
    model: Short | None = None
    serial_number: Short | None = None
    bios_version: Short | None = None


class SecurityCheck(_Strict):
    # Tri/quad-state result; the agent must report "unknown" when it cannot determine the state.
    state: Literal["enabled", "disabled", "partial", "unknown", "not_applicable"]
    detail: Annotated[str, StringConstraints(max_length=512)] | None = None
    data: dict[str, str | int | bool | None] = Field(default_factory=dict, max_length=32)


class InventoryRequest(_Strict):
    agent_version: Tiny
    collected_at: datetime | None = None
    hostname: str = Field(pattern=HOSTNAME_RE)
    os: OSInfo
    hardware: HardwareInfo
    cpu: CPUInfo
    memory_bytes: int | None = Field(default=None, ge=0, le=2**50)
    disks: list[DiskInfo] = Field(default_factory=list, max_length=64)
    network_interfaces: list[NetInterface] = Field(default_factory=list, max_length=64)
    security: dict[Tiny, SecurityCheck] = Field(default_factory=dict, max_length=32)
    collection_errors: list[Annotated[str, StringConstraints(max_length=256)]] = Field(default_factory=list, max_length=32)

    @field_validator("security")
    @classmethod
    def _keys(cls, v: dict) -> dict:
        for k in v:
            if not k.replace("_", "").isalnum():
                raise ValueError("invalid security check key")
        return v


class RenewRequest(_Strict):
    csr_pem: str = Field(min_length=100, max_length=4096)


class RenewResponse(BaseModel):
    certificate_pem: str
    not_after: datetime


# ---------------------------------------------------------------------------------------------- admin
class EnrollmentTokenCreate(BaseModel):
    label: str = Field(min_length=2, max_length=128)
    employee_id: uuid.UUID | None = None
    expires_in_minutes: int = Field(default=60, ge=5, le=1440)


class EnrollmentTokenOut(ORMModel):
    id: uuid.UUID
    label: str
    employee_id: uuid.UUID | None
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None
    used_by_device_id: uuid.UUID | None
    revoked_at: datetime | None
    state: str = "active"


class EnrollmentTokenCreated(EnrollmentTokenOut):
    token: str  # shown exactly once


class DeviceOut(ORMModel):
    id: uuid.UUID
    display_name: str
    hostname: str
    employee_id: uuid.UUID | None
    employee_name: str | None = None
    support_owner_id: uuid.UUID | None
    os_name: str | None
    os_version: str | None
    os_build: str | None
    manufacturer: str | None
    model: str | None
    serial_number: str | None
    agent_version: str | None
    status: str
    compliance_state: str
    enrolled_at: datetime
    last_heartbeat_at: datetime | None
    last_inventory_at: datetime | None
    last_seen_ip: str | None
    reported_ip_addresses: dict
    reported_mac_addresses: dict
    online: bool = False
    connectivity: str = "never"  # online | offline | never


class InventoryOut(ORMModel):
    id: uuid.UUID
    collected_at: datetime
    agent_collected_at: datetime | None
    cpu: dict
    memory_bytes: int | None
    disks: dict
    network_interfaces: dict
    security: dict
    os: dict


class CertificateOut(ORMModel):
    id: uuid.UUID
    serial: str
    fingerprint_sha256: str
    not_before: datetime
    not_after: datetime
    status: str
    revoked_at: datetime | None
    revoked_reason: str | None
    created_at: datetime


class DeviceEventOut(ORMModel):
    id: uuid.UUID
    kind: str
    details: dict
    actor_id: uuid.UUID | None
    created_at: datetime


class HeartbeatOut(ORMModel):
    received_at: datetime
    source_ip: str | None
    agent_version: str | None
    uptime_seconds: int | None


class DeviceUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=128)
    employee_id: uuid.UUID | None = None
    support_owner_id: uuid.UUID | None = None


class DeviceActionRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)
