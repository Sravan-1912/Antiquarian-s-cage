"""SIEM / webhook egress: per-org destination config + a durable delivery outbox."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "siem_destinations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("auth_header", sa.String(64), nullable=False, server_default="Authorization"),
        sa.Column("token_enc", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("min_severity", sa.String(12), nullable=False, server_default="low"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("last_success_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(500), nullable=True),
    )
    op.create_table(
        "siem_deliveries",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(12), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=False),
        sa.Column("sent_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_siem_deliv_status_next", "siem_deliveries", ["status", "next_attempt_at"])


def downgrade() -> None:
    op.drop_index("ix_siem_deliv_status_next", table_name="siem_deliveries")
    op.drop_table("siem_deliveries")
    op.drop_table("siem_destinations")
