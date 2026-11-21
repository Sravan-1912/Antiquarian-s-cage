"""Per-organization geo-security policy (geo-fencing + impossible-travel detection)."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "geo_security_policies",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("geofence_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("allowed_countries", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("on_violation", sa.String(12), nullable=False, server_default="alert"),
        sa.Column("impossible_travel", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("geo_security_policies")
