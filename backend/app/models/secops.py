"""Security alerts, alert history, notification preferences and the durable email outbox."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import utcnow
from app.models.base import Base, Timestamps, UUIDPk


class SecurityAlert(UUIDPk, Timestamps, Base):
    __tablename__ = "security_alerts"
    __table_args__ = (Index("ix_alerts_org_status", "organization_id", "status"),
                      Index("ix_alerts_org_detected", "organization_id", "detected_at"),
                      Index("ix_alerts_dedup_open", "organization_id", "dedup_key", "status"))

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    owner_admin_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)  # admin isolation
    rule_key: Mapped[str] = mapped_column(String(48))
    # configuration | operational | suspicious_activity — never "attack": an alert is a lead, not a verdict.
    kind: Mapped[str] = mapped_column(String(24))
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))  # critical | high | medium | low | informational
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"), index=True)
    employee_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("employees.id", ondelete="SET NULL"))
    subject_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    subject_label: Mapped[str | None] = mapped_column(String(320))
    detected_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    # new | triaging | investigating | resolved | false_positive
    status: Mapped[str] = mapped_column(String(16), default="new")
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    resolution_notes: Mapped[str | None] = mapped_column(Text)
    resolved_at: Mapped[datetime | None]
    auto_resolvable: Mapped[bool] = mapped_column(Boolean, default=False)
    dedup_key: Mapped[str] = mapped_column(String(200))
    evidence: Mapped[dict] = mapped_column(default=dict)


class AlertEvent(UUIDPk, Base):
    __tablename__ = "alert_events"
    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("security_alerts.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(24))  # created | reoccurred | status | assigned | note | auto_resolved
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    actor_label: Mapped[str] = mapped_column(String(320))
    details: Mapped[dict] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class NotificationPreference(UUIDPk, Base):
    __tablename__ = "notification_preferences"
    __table_args__ = (UniqueConstraint("user_id", "category"),)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    category: Mapped[str] = mapped_column(String(32))
    in_app: Mapped[bool] = mapped_column(Boolean, default=True)
    email: Mapped[bool] = mapped_column(Boolean, default=False)
    min_severity: Mapped[str] = mapped_column(String(16), default="informational")  # in-app threshold
    email_min_severity: Mapped[str] = mapped_column(String(16), default="high")


class EmailOutbox(UUIDPk, Base):
    """Durable queue: emails are committed with the triggering transaction and delivered by the scheduler with
    retries, so a mail-server outage never silently drops a security notification."""

    __tablename__ = "email_outbox"
    __table_args__ = (Index("ix_outbox_status_next", "status", "next_attempt_at"),)
    to_address: Mapped[str] = mapped_column(String(320))
    subject: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(12), default="pending")  # pending | sent | failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    next_attempt_at: Mapped[datetime] = mapped_column(default=utcnow)
    sent_at: Mapped[datetime | None]
