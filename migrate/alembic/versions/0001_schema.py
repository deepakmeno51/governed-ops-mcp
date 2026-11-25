"""tables: users, orders, app_logs, tickets, ticket_comments, approvals, audit_events"""
from pathlib import Path

from alembic import op

revision = "0001"
down_revision = None

SQL = Path(__file__).resolve().parent.parent / "sql" / "0001_schema.sql"


def upgrade():
    op.get_bind().exec_driver_sql(SQL.read_text())


def downgrade():
    op.get_bind().exec_driver_sql(
        "DROP TABLE IF EXISTS audit_events, approvals, ticket_comments, tickets, app_logs, orders, users CASCADE"
    )
