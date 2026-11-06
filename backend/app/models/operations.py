from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import utcnow
from app.models.base import Base, UUIDPk


class AuditLog(UUIDPk, Base):
    """Append-only, hash-chained administrative audit log (see services/audit.py)."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        UniqueConstraint("organization_id", "seq"),
        Index("ix_audit_org_created", "organization_id", "created_at"),
        Index("ix_audit_org_action", "organization_id", "action"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    seq: Mapped[int] = mapped_column(BigInteger)
    actor_type: Mapped[str] = mapped_column(String(16))  # user | system | device
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    actor_label: Mapped[str] = mapped_column(String(320))
    action: Mapped[str] = mapped_column(String(64))
    target_type: Mapped[str | None] = mapped_column(String(48))
    target_id: Mapped[str | None] = mapped_column(String(64))
    target_label: Mapped[str | None] = mapped_column(String(320))
    source_ip: Mapped[str | None] = mapped_column(String(64))
    result: Mapped[str] = mapped_column(String(16))  # success | failure | denied
    event_metadata: Mapped[dict] = mapped_column("metadata", default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
    mac: Mapped[str] = mapped_column(String(64))


class AuditAnchor(UUIDPk, Base):
    """Signed snapshot of the audit chain head. Also appended to an external file (AUDIT_ANCHOR_DIR) so that deleting
    or rewriting the tail of the chain - even by someone holding the HMAC key and DB owner rights - is detectable."""

    __tablename__ = "audit_anchors"
    __table_args__ = (UniqueConstraint("organization_id", "seq"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    seq: Mapped[int] = mapped_column(BigInteger)
    hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    key_id: Mapped[str] = mapped_column(String(40))
    signature: Mapped[str] = mapped_column(String(128))
    external_written: Mapped[bool] = mapped_column(default=False)
    external_error: Mapped[str | None] = mapped_column(String(300))


class Notification(UUIDPk, Base):
    __tablename__ = "notifications"
    __table_args__ = (Index("ix_notifications_user_read", "user_id", "read_at"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(48))
    severity: Mapped[str] = mapped_column(String(16), default="info")
    category: Mapped[str] = mapped_column(String(32), default="general", server_default="general")
    title: Mapped[str] = mapped_column(String(200))
    body: Mapped[str] = mapped_column(Text, default="")
    link: Mapped[str | None] = mapped_column(String(255))
    read_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
