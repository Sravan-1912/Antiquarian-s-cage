from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import utcnow
from app.models.base import Base, Timestamps, UUIDPk


class Device(UUIDPk, Timestamps, Base):
    """An enrolled endpoint. Hardware/OS fields are *reported by the agent* and must not be treated as verified."""

    __tablename__ = "devices"
    __table_args__ = (
        Index("ix_devices_org_status", "organization_id", "status"),
        Index("ix_devices_org_heartbeat", "organization_id", "last_heartbeat_at"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    employee_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("employees.id", ondelete="SET NULL"), index=True)
    support_owner_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    display_name: Mapped[str] = mapped_column(String(128))
    hostname: Mapped[str] = mapped_column(String(64))
    os_name: Mapped[str | None] = mapped_column(String(128))
    os_version: Mapped[str | None] = mapped_column(String(64))
    os_build: Mapped[str | None] = mapped_column(String(64))
    manufacturer: Mapped[str | None] = mapped_column(String(128))
    model: Mapped[str | None] = mapped_column(String(128))
    serial_number: Mapped[str | None] = mapped_column(String(128))
    agent_version: Mapped[str | None] = mapped_column(String(32))
    # active | suspended | revoked | unenrolled
    status: Mapped[str] = mapped_column(String(16), default="active")
    # unknown until the compliance engine (Phase 3) evaluates the device
    compliance_state: Mapped[str] = mapped_column(String(16), default="unknown")
    enrolled_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_heartbeat_at: Mapped[datetime | None]
    last_inventory_at: Mapped[datetime | None]
    last_seen_ip: Mapped[str | None] = mapped_column(String(64))  # observed by the server, not reported
    reported_ip_addresses: Mapped[dict] = mapped_column(default=dict)
    reported_mac_addresses: Mapped[dict] = mapped_column(default=dict)


class EnrollmentToken(UUIDPk, Base):
    __tablename__ = "enrollment_tokens"
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    label: Mapped[str] = mapped_column(String(128))
    employee_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("employees.id", ondelete="SET NULL"))
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]
    used_by_device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    revoked_at: Mapped[datetime | None]


class DeviceCertificate(UUIDPk, Base):
    __tablename__ = "device_certificates"
    __table_args__ = (Index("ix_device_certs_device_status", "device_id", "status"),)
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    serial: Mapped[str] = mapped_column(String(64), unique=True)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    public_key_pem: Mapped[str] = mapped_column(Text)
    certificate_pem: Mapped[str] = mapped_column(Text)
    not_before: Mapped[datetime]
    not_after: Mapped[datetime]
    # active | superseded | revoked
    status: Mapped[str] = mapped_column(String(16), default="active")
    revoked_at: Mapped[datetime | None]
    revoked_reason: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class AgentRequestNonce(Base):
    """Replay protection for signed agent requests (rows expire with the timestamp window)."""

    __tablename__ = "agent_request_nonces"
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(index=True)


class DeviceHeartbeat(Base):
    __tablename__ = "device_heartbeats"
    __table_args__ = (Index("ix_heartbeats_device_received", "device_id", "received_at"),)
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    received_at: Mapped[datetime] = mapped_column(default=utcnow)
    source_ip: Mapped[str | None] = mapped_column(String(64))
    agent_version: Mapped[str | None] = mapped_column(String(32))
    uptime_seconds: Mapped[int | None] = mapped_column(BigInteger)


class DeviceInventory(UUIDPk, Base):
    __tablename__ = "device_inventory"
    __table_args__ = (Index("ix_inventory_device_collected", "device_id", "collected_at"),)
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    collected_at: Mapped[datetime] = mapped_column(default=utcnow)  # server receive time
    agent_collected_at: Mapped[datetime | None]  # agent clock, informational only
    cpu: Mapped[dict] = mapped_column(default=dict)
    memory_bytes: Mapped[int | None] = mapped_column(BigInteger)
    disks: Mapped[dict] = mapped_column(default=dict)
    network_interfaces: Mapped[dict] = mapped_column(default=dict)
    security: Mapped[dict] = mapped_column(default=dict)
    os: Mapped[dict] = mapped_column(default=dict)


class DeviceEvent(UUIDPk, Base):
    """Device lifecycle history (enrolled, suspended, revoked, assigned, cert renewed, …)."""

    __tablename__ = "device_events"
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    details: Mapped[dict] = mapped_column(default=dict)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class AgentVersion(UUIDPk, Base):
    __tablename__ = "agent_versions"
    __table_args__ = (UniqueConstraint("version", "channel"),)
    version: Mapped[str] = mapped_column(String(32))
    channel: Mapped[str] = mapped_column(String(16), default="stable")
    sha256: Mapped[str] = mapped_column(String(64))
    released_at: Mapped[datetime] = mapped_column(default=utcnow)
    revoked: Mapped[bool] = mapped_column(default=False)
