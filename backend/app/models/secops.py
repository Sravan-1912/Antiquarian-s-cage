"""Security alerts, alert history, notification preferences and the durable email outbox."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, ForeignKey, Index, Integer, String, Text, UniqueConstraint
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


class SiemDestination(UUIDPk, Base):
    """Per-organization SIEM / webhook egress config. Security alerts are POSTed here as JSON so a SOC's
    Splunk/Elastic/Datadog receives them. The token is stored AES-256-GCM-encrypted (never returned to the client)."""

    __tablename__ = "siem_destinations"
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), unique=True)
    url: Mapped[str] = mapped_column(String(2048))
    auth_header: Mapped[str] = mapped_column(String(64), default="Authorization")
    token_enc: Mapped[str | None] = mapped_column(Text)        # encrypted bearer / HEC token, or NULL
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    min_severity: Mapped[str] = mapped_column(String(12), default="low")  # low | medium | high | critical
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_success_at: Mapped[datetime | None]
    last_error: Mapped[str | None] = mapped_column(String(500))


class SiemDelivery(UUIDPk, Base):
    """Durable outbox for SIEM egress — committed with the alert transaction, delivered by the scheduler with retries,
    so a SIEM outage never silently drops a security event."""

    __tablename__ = "siem_deliveries"
    __table_args__ = (Index("ix_siem_deliv_status_next", "status", "next_attempt_at"),)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    payload: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(12), default="pending")  # pending | sent | failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    next_attempt_at: Mapped[datetime] = mapped_column(default=utcnow)
    sent_at: Mapped[datetime | None]


class GeoSecurityPolicy(UUIDPk, Base):
    """Per-organization location-security config: geo-fencing (allowed countries) and impossible-travel detection.
    Evaluated whenever an endpoint reports a resolved location. One row per organization."""

    __tablename__ = "geo_security_policies"
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), unique=True)
    geofence_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    allowed_countries: Mapped[list] = mapped_column(JSON, default=list)   # e.g. ["India", "United States"]
    on_violation: Mapped[str] = mapped_column(String(12), default="alert")  # alert | isolate
    impossible_travel: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow)


class ChatWebhook(UUIDPk, Base):
    """Per-org chat alert channel — Slack / Microsoft Teams / Discord / generic JSON webhook. The webhook URL is a
    secret (it grants posting), so it is stored AES-256-GCM-encrypted and never returned to clients."""

    __tablename__ = "chat_webhooks"
    __table_args__ = (UniqueConstraint("organization_id", "platform", name="uq_chat_org_platform"),)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    platform: Mapped[str] = mapped_column(String(12))  # slack | teams | discord | generic
    url_enc: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    min_severity: Mapped[str] = mapped_column(String(12), default="high")
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_success_at: Mapped[datetime | None]
    last_error: Mapped[str | None] = mapped_column(String(500))


class ChatDelivery(UUIDPk, Base):
    """Durable outbox for chat-channel alert posts (per webhook), delivered by the scheduler with retries."""

    __tablename__ = "chat_deliveries"
    __table_args__ = (Index("ix_chat_deliv_status_next", "status", "next_attempt_at"),)
    webhook_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("chat_webhooks.id", ondelete="CASCADE"), index=True)
    payload: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(12), default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    next_attempt_at: Mapped[datetime] = mapped_column(default=utcnow)
    sent_at: Mapped[datetime | None]


class ResponsePlaybook(UUIDPk, Base):
    """Automated response (SOAR): when a security alert matches the trigger, run the listed actions
    (isolate the endpoint, escalate to critical, add a note). One organization may have several playbooks."""

    __tablename__ = "response_playbooks"
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    match_rule_keys: Mapped[list] = mapped_column(JSON, default=list)   # [] = any rule
    match_min_severity: Mapped[str] = mapped_column(String(12), default="high")
    match_kinds: Mapped[list] = mapped_column(JSON, default=list)       # [] = any kind
    actions: Mapped[list] = mapped_column(JSON, default=list)           # ["isolate", "escalate", "comment"]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow)
