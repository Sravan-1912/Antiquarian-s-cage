"""Dynamic endpoint groups: a saved set of filter criteria that resolves to a *live* set of endpoints (membership is
computed from device attributes at query time, never a stored list). Groups are the target for bulk actions — deploy a
script, run a remote action, or change status across every current member at once.
"""
from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, Timestamps, UUIDPk


class DeviceGroup(UUIDPk, Timestamps, Base):
    __tablename__ = "device_groups"
    __table_args__ = (Index("ix_device_groups_org", "organization_id"),)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    owner_admin_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)  # admin isolation
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(String(500), default="")
    # Criteria: all present keys are ANDed. Keys: q (text), status, connectivity (online|offline|never),
    # os (os_name substring), compliance_state (compliant|non_compliant|unknown).
    criteria: Mapped[dict] = mapped_column(default=dict)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
