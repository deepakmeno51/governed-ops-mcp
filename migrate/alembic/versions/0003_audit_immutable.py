"""block UPDATE, DELETE and TRUNCATE on audit_events"""
from pathlib import Path

from alembic import op

revision = "0003"
down_revision = "0002"

SQL = Path(__file__).resolve().parent.parent / "sql" / "0003_audit_immutable.sql"


def upgrade():
    op.get_bind().exec_driver_sql(SQL.read_text())


def downgrade():
    conn = op.get_bind()
    conn.exec_driver_sql("DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events")
    conn.exec_driver_sql("DROP TRIGGER IF EXISTS audit_events_no_update_delete ON audit_events")
    conn.exec_driver_sql("DROP FUNCTION IF EXISTS audit_events_immutable()")
