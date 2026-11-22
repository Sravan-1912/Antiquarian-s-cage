"""Dynamic endpoint groups (saved filter criteria)."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "device_groups",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("owner_admin_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.String(500), nullable=False, server_default=""),
        sa.Column("criteria", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_device_groups_org", "device_groups", ["organization_id"])
    op.create_index("ix_device_groups_owner_admin_id", "device_groups", ["owner_admin_id"])


def downgrade() -> None:
    op.drop_index("ix_device_groups_owner_admin_id", table_name="device_groups")
    op.drop_index("ix_device_groups_org", table_name="device_groups")
    op.drop_table("device_groups")
