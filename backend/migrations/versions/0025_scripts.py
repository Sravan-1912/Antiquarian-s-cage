"""Scripts library + per-endpoint script runs."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scripts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("owner_admin_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.String(500), nullable=False, server_default=""),
        sa.Column("interpreter", sa.String(16), nullable=False, server_default="powershell"),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_scripts_org", "scripts", ["organization_id"])
    op.create_index("ix_scripts_owner_admin_id", "scripts", ["owner_admin_id"])
    op.create_table(
        "script_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("script_id", sa.Uuid(), sa.ForeignKey("scripts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("device_id", sa.Uuid(), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("command_job_id", sa.Uuid(), sa.ForeignKey("command_jobs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("script_name", sa.String(128), nullable=False, server_default=""),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("stdout", sa.Text(), nullable=False, server_default=""),
        sa.Column("stderr", sa.Text(), nullable=False, server_default=""),
        sa.Column("requested_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("requested_by_label", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_script_runs_script", "script_runs", ["script_id"])
    op.create_index("ix_script_runs_org", "script_runs", ["organization_id"])
    op.create_index("ix_script_runs_device", "script_runs", ["device_id"])
    op.create_index("ix_script_runs_job", "script_runs", ["command_job_id"])


def downgrade() -> None:
    op.drop_table("script_runs")
    op.drop_index("ix_scripts_owner_admin_id", table_name="scripts")
    op.drop_index("ix_scripts_org", table_name="scripts")
    op.drop_table("scripts")
