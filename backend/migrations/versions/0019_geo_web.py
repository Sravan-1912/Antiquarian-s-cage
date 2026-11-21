"""Endpoint geolocation (latest, with accuracy + source) and aggregated per-domain web activity."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "device_locations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("device_id", sa.Uuid(), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("source", sa.String(8), nullable=False, server_default="none"),
        sa.Column("latitude", sa.Float(), nullable=True),
        sa.Column("longitude", sa.Float(), nullable=True),
        sa.Column("accuracy_m", sa.Integer(), nullable=True),
        sa.Column("city", sa.String(128), nullable=True),
        sa.Column("region", sa.String(128), nullable=True),
        sa.Column("country", sa.String(64), nullable=True),
        sa.Column("ip", sa.String(64), nullable=True),
        sa.Column("ap_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("resolved_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_device_locations_device_id", "device_locations", ["device_id"])
    op.create_table(
        "device_site_visits",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("device_id", sa.Uuid(), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("visits", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("device_id", "domain", name="uq_site_visit_device_domain"),
    )
    op.create_index("ix_site_visits_device", "device_site_visits", ["device_id"])


def downgrade() -> None:
    op.drop_index("ix_site_visits_device", table_name="device_site_visits")
    op.drop_table("device_site_visits")
    op.drop_index("ix_device_locations_device_id", table_name="device_locations")
    op.drop_table("device_locations")
