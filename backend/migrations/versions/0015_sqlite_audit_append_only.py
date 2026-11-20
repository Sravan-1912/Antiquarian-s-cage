"""SQLite append-only triggers for the audit tables (PostgreSQL already has equivalents)

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-16

On PostgreSQL the audit_logs / audit_anchors tables are protected by BEFORE UPDATE/DELETE/TRUNCATE
triggers (migrations 0001/0007). SQLite deployments (the desktop app, the test suite) had no such
protection. These row-level BEFORE UPDATE/DELETE triggers make those tables append-only on SQLite
too, so the audit hash-chain cannot be rewritten even with direct database access.
"""
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

TABLES = ("audit_logs", "audit_anchors")


def upgrade() -> None:
    if op.get_bind().dialect.name != "sqlite":
        return
    for tbl in TABLES:
        for verb in ("UPDATE", "DELETE"):
            op.execute(
                f"CREATE TRIGGER {tbl}_no_{verb.lower()} BEFORE {verb} ON {tbl} "
                f"BEGIN SELECT RAISE(ABORT, '{tbl} is append-only'); END"
            )


def downgrade() -> None:
    if op.get_bind().dialect.name != "sqlite":
        return
    for tbl in TABLES:
        for verb in ("update", "delete"):
            op.execute(f"DROP TRIGGER IF EXISTS {tbl}_no_{verb}")
