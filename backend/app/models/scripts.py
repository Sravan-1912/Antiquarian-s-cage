"""Scripts library + deployment: reusable, versioned scripts an operator can run on one or more endpoints.

A `Script` is authored once (PowerShell / cmd / bash) and deployed to endpoints as signed, allowlisted `script.run`
command jobs — the same signed-envelope pipeline every other remote action uses. Each per-endpoint execution is a
`ScriptRun` that captures the exit code and (capped) stdout/stderr. This is a managed, audited, RBAC-gated capability
(gated on `devices:shell`, the same class as the break-glass live-response shell): scripts run in the agent's service
context, never as an arbitrary ad-hoc command path.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import utcnow
from app.models.base import Base, Timestamps, UUIDPk


class Script(UUIDPk, Timestamps, Base):
    __tablename__ = "scripts"
    __table_args__ = (Index("ix_scripts_org", "organization_id"),)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    owner_admin_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)  # admin isolation
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(String(500), default="")
    interpreter: Mapped[str] = mapped_column(String(16), default="powershell")  # powershell | cmd | bash
    content: Mapped[str] = mapped_column(Text)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=300)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ScriptRun(UUIDPk, Base):
    """One endpoint's execution of a script. `command_job_id` links to the signed CommandJob; results (exit code +
    captured output) are recorded when the agent reports the job result."""

    __tablename__ = "script_runs"
    __table_args__ = (Index("ix_script_runs_script", "script_id"), Index("ix_script_runs_job", "command_job_id"))
    script_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scripts.id", ondelete="CASCADE"), index=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    command_job_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("command_jobs.id", ondelete="SET NULL"))
    script_name: Mapped[str] = mapped_column(String(128), default="")  # snapshot of the name at deploy time
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued | succeeded | failed | needs_attention | rejected
    exit_code: Mapped[int | None] = mapped_column(Integer)
    stdout: Mapped[str] = mapped_column(Text, default="")
    stderr: Mapped[str] = mapped_column(Text, default="")
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    requested_by_label: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[datetime | None]
