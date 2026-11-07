"""phase12 subscriptions and device quotas

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-07
"""
from alembic import op
import sqlalchemy as sa
import app.core.database

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "subscription_plans",
        sa.Column("key", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("max_device_slots", sa.Integer(), nullable=True),
        sa.Column("monthly_price_cents", sa.Integer(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", app.core.database.UTCDateTime(timezone=True), nullable=False),
        sa.Column("updated_at", app.core.database.UTCDateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_subscription_plans")),
        sa.UniqueConstraint("key", name=op.f("uq_subscription_plans_key")),
    )
    op.create_table(
        "subscriptions",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("owner_admin_id", sa.Uuid(), nullable=True),
        sa.Column("plan_key", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("max_device_slots", sa.Integer(), nullable=True),
        sa.Column("current_period_end", app.core.database.UTCDateTime(timezone=True), nullable=True),
        sa.Column("created_at", app.core.database.UTCDateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("updated_at", app.core.database.UTCDateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"],
                                name=op.f("fk_subscriptions_organization_id_organizations")),
        sa.ForeignKeyConstraint(["owner_admin_id"], ["users.id"], ondelete="CASCADE",
                                name=op.f("fk_subscriptions_owner_admin_id_users")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_subscriptions")),
        sa.UniqueConstraint("organization_id", "owner_admin_id", name=op.f("uq_subscriptions_organization_id_owner_admin_id")),
    )
    op.create_index(op.f("ix_subscriptions_organization_id"), "subscriptions", ["organization_id"])
    op.create_index(op.f("ix_subscriptions_owner_admin_id"), "subscriptions", ["owner_admin_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_subscriptions_owner_admin_id"), table_name="subscriptions")
    op.drop_index(op.f("ix_subscriptions_organization_id"), table_name="subscriptions")
    op.drop_table("subscriptions")
    op.drop_table("subscription_plans")
