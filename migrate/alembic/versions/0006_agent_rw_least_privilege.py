"""agent_rw may update only the columns the SQL guard allows"""
from pathlib import Path

from alembic import op

revision = "0006"
down_revision = "0005"

SQL = Path(__file__).resolve().parent.parent / "sql" / "0006_agent_rw_least_privilege.sql"


def upgrade():
    op.get_bind().exec_driver_sql(SQL.read_text())


def downgrade():
    conn = op.get_bind()
    conn.exec_driver_sql("REVOKE UPDATE (status) ON orders FROM agent_rw")
    conn.exec_driver_sql("REVOKE UPDATE (status, severity) ON tickets FROM agent_rw")
    conn.exec_driver_sql("GRANT UPDATE ON orders, tickets TO agent_rw")
