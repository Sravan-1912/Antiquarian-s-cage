from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import Date, ForeignKey, Index, String, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import utcnow
from app.models.base import Base, Timestamps, UUIDPk


class Employee(UUIDPk, Timestamps, Base):
    __tablename__ = "employees"
    __table_args__ = (
        UniqueConstraint("organization_id", "employee_number"),
        Index("uq_employees_org_email", "organization_id", text("lower(email)"), unique=True),
        Index("ix_employees_org_status", "organization_id", "status"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    owner_admin_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)  # admin isolation
    employee_number: Mapped[str] = mapped_column(String(32))
    full_name: Mapped[str] = mapped_column(String(200))
    email: Mapped[str] = mapped_column(String(320))
    department: Mapped[str] = mapped_column(String(100))
    job_title: Mapped[str] = mapped_column(String(150))
    # invited | active | suspended | offboarded
    status: Mapped[str] = mapped_column(String(16), default="active")
    # not_enrolled | enrolled (updated by the endpoint module in Phase 2)
    enrollment_status: Mapped[str] = mapped_column(String(16), default="not_enrolled")
    manager_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("employees.id", ondelete="SET NULL"))
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    start_date: Mapped[date | None] = mapped_column(Date)
    end_date: Mapped[date | None] = mapped_column(Date)


class EmployeeEvent(UUIDPk, Base):
    """Joiner / mover / leaver history."""

    __tablename__ = "employee_events"
    employee_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("employees.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(24))
    details: Mapped[dict] = mapped_column(default=dict)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
