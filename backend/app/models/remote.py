"""Remote assistance sessions. Remote one-shot actions (lock, restart, inspect, account management) are CommandJobs."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import utcnow
from app.models.base import Base, UUIDPk


class RemoteSession(UUIDPk, Base):
    __tablename__ = "remote_sessions"
    __table_args__ = (Index("ix_remote_sessions_device_status", "device_id", "status"),
                      Index("ix_remote_sessions_org_created", "organization_id", "created_at"))

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    requested_by_label: Mapped[str] = mapped_column(String(320))
    reason: Mapped[str] = mapped_column(Text)
    require_consent: Mapped[bool] = mapped_column(Boolean, default=True)
    max_minutes: Mapped[int] = mapped_column(Integer)
    # requested | awaiting_consent | active | ending | ended | denied | expired | cancelled | failed
    status: Mapped[str] = mapped_column(String(20), default="requested")
    start_job_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("command_jobs.id", ondelete="SET NULL"))
    end_job_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("command_jobs.id", ondelete="SET NULL"))
    consent_decision: Mapped[str | None] = mapped_column(String(16))  # granted | denied | timeout | not_required
    consent_user: Mapped[str | None] = mapped_column(String(128))  # Windows account that answered (reported)
    consented_at: Mapped[datetime | None]
    started_at: Mapped[datetime | None]
    expires_at: Mapped[datetime | None]
    ended_at: Mapped[datetime | None]
    ended_by: Mapped[str | None] = mapped_column(String(32))  # endpoint_user | administrator | expiry | system
    end_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
