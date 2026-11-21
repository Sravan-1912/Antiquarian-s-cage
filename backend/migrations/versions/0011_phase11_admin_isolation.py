"""phase11 admin isolation (owner_admin_id)

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-07
"""
from alembic import op
import sqlalchemy as sa

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None

TABLES = ("users", "employees", "devices", "enrollment_tokens", "endpoint_policies", "security_alerts")


def upgrade() -> None:
    for t in TABLES:
        with op.batch_alter_table(t, schema=None) as b:
            b.add_column(sa.Column("owner_admin_id", sa.Uuid(), nullable=True))
            b.create_index(op.f(f"ix_{t}_owner_admin_id"), ["owner_admin_id"])
            b.create_foreign_key(op.f(f"fk_{t}_owner_admin_id_users"), "users", ["owner_admin_id"], ["id"],
                                 ondelete="SET NULL")


def downgrade() -> None:
    for t in TABLES:
        with op.batch_alter_table(t, schema=None) as b:
            b.drop_constraint(op.f(f"fk_{t}_owner_admin_id_users"), type_="foreignkey")
            b.drop_index(op.f(f"ix_{t}_owner_admin_id"))
            b.drop_column("owner_admin_id")
