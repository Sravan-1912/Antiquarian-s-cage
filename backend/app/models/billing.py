from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import utcnow
from app.models.base import Base, Timestamps, UUIDPk


class SubscriptionPlan(UUIDPk, Timestamps, Base):
    """Catalogue of plans, synchronised from app/services/subscriptions.py at startup (like roles/permissions).

    `max_device_slots` NULL means unlimited.
    """

    __tablename__ = "subscription_plans"
    key: Mapped[str] = mapped_column(String(32), unique=True)
    name: Mapped[str] = mapped_column(String(80))
    max_device_slots: Mapped[int | None] = mapped_column(Integer)
    monthly_price_cents: Mapped[int] = mapped_column(Integer, default=0)
    is_active: Mapped[bool] = mapped_column(default=True)


class Subscription(UUIDPk, Timestamps, Base):
    """A plan assigned to a tenant. `owner_admin_id` NULL is the organisation-wide default plan that applies to any
    admin without their own subscription. Resolution order at enrolment: the admin's own subscription, then the
    organisation default, then the built-in default plan."""

    __tablename__ = "subscriptions"
    __table_args__ = (UniqueConstraint("organization_id", "owner_admin_id"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    owner_admin_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    plan_key: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | past_due | cancelled
    # Effective slot cap for this subscription (copied from the plan, overridable by a Super Admin). NULL = unlimited.
    max_device_slots: Mapped[int | None] = mapped_column(Integer)
    current_period_end: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
