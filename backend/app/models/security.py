"""Policy engine, signed command jobs and compliance evaluation."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import utcnow
from app.models.base import Base, Timestamps, UUIDPk


class EndpointPolicy(UUIDPk, Timestamps, Base):
    __tablename__ = "endpoint_policies"
    __table_args__ = (UniqueConstraint("organization_id", "name"), Index("ix_policies_org_category", "organization_id", "category"))
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    # firewall | bitlocker | usb | antivirus | screen_lock | windows_update | password
    category: Mapped[str] = mapped_column(String(32))
    configuration: Mapped[dict] = mapped_column(default=dict)
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | retired
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class PolicyRevision(UUIDPk, Base):
    __tablename__ = "policy_revisions"
    __table_args__ = (UniqueConstraint("policy_id", "version"),)
    policy_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("endpoint_policies.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    configuration: Mapped[dict] = mapped_column(default=dict)
    changed_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class PolicyAssignment(UUIDPk, Base):
    __tablename__ = "policy_assignments"
    __table_args__ = (Index("ix_assignments_policy_device", "policy_id", "device_id"),)
    policy_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("endpoint_policies.id", ondelete="CASCADE"))
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    assigned_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    assigned_at: Mapped[datetime] = mapped_column(default=utcnow)
    revoked_at: Mapped[datetime | None]
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class CommandJob(UUIDPk, Base):
    """A signed, expiring, single-use instruction for one device. Only allowlisted commands can be created."""

    __tablename__ = "command_jobs"
    __table_args__ = (Index("ix_jobs_device_status", "device_id", "status"),)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    command: Mapped[str] = mapped_column(String(64))
    parameters: Mapped[dict] = mapped_column(default=dict)
    envelope: Mapped[dict] = mapped_column(default=dict)  # exact signed payload delivered to the agent
    nonce: Mapped[str] = mapped_column(String(64), unique=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True)
    key_id: Mapped[str] = mapped_column(String(32))
    signature: Mapped[str] = mapped_column(Text)
    issued_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime]
    # queued | delivered | succeeded | failed | expired | revoked
    status: Mapped[str] = mapped_column(String(16), default="queued")
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    delivered_at: Mapped[datetime | None]
    completed_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
    result: Mapped[dict] = mapped_column(default=dict)


class PolicyDeployment(UUIDPk, Timestamps, Base):
    __tablename__ = "policy_deployments"
    __table_args__ = (Index("ix_deployments_policy_status", "policy_id", "status"),)
    policy_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("endpoint_policies.id", ondelete="CASCADE"))
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    assignment_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("policy_assignments.id", ondelete="SET NULL"))
    policy_version: Mapped[int] = mapped_column(Integer)
    action: Mapped[str] = mapped_column(String(16))  # apply | remove
    command_job_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("command_jobs.id", ondelete="SET NULL"))
    # pending | in_progress | applied | failed | offline | needs_attention | revoked
    status: Mapped[str] = mapped_column(String(20), default="pending")
    detail: Mapped[str | None] = mapped_column(Text)
    result: Mapped[dict] = mapped_column(default=dict)
    previous_state: Mapped[dict] = mapped_column(default=dict)


class ComplianceCheckSetting(UUIDPk, Base):
    """Organisation overrides for the built-in compliance check catalogue (enable/disable, severity)."""

    __tablename__ = "compliance_check_settings"
    __table_args__ = (UniqueConstraint("organization_id", "check_key"),)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    check_key: Mapped[str] = mapped_column(String(48))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    severity: Mapped[str] = mapped_column(String(16))
    updated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)


class ComplianceEvaluation(UUIDPk, Base):
    __tablename__ = "compliance_evaluations"
    __table_args__ = (Index("ix_evaluations_device_time", "device_id", "evaluated_at"),
                      Index("ix_evaluations_org_time", "organization_id", "evaluated_at"))
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    inventory_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("device_inventory.id", ondelete="SET NULL"))
    evaluated_at: Mapped[datetime] = mapped_column(default=utcnow)
    state: Mapped[str] = mapped_column(String(16))  # compliant | non_compliant | unknown
    score: Mapped[int] = mapped_column(Integer)  # 0..100 (PASS / applicable; UNKNOWN counts as not passed)
    passed: Mapped[int] = mapped_column(Integer)
    failed: Mapped[int] = mapped_column(Integer)
    unknown: Mapped[int] = mapped_column(Integer)
    not_applicable: Mapped[int] = mapped_column(Integer)


class ComplianceResult(UUIDPk, Base):
    __tablename__ = "compliance_results"
    __table_args__ = (Index("ix_results_eval", "evaluation_id"), Index("ix_results_check_result", "check_key", "result"))
    evaluation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("compliance_evaluations.id", ondelete="CASCADE"))
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    check_key: Mapped[str] = mapped_column(String(48))
    result: Mapped[str] = mapped_column(String(16))  # PASS | FAIL | UNKNOWN | NOT_APPLICABLE
    severity: Mapped[str] = mapped_column(String(16))
    evidence: Mapped[dict] = mapped_column(default=dict)
