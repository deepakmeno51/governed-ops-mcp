"""roles (agent_ro, agent_rw, audit_writer), redaction function, views"""
import os
from pathlib import Path

from alembic import op

revision = "0002"
down_revision = "0001"

SQL = Path(__file__).resolve().parent.parent / "sql" / "0002_roles_views.sql"
ROLES = (
    ("agent_ro", "AGENT_RO_PASSWORD"),
    ("agent_rw", "AGENT_RW_PASSWORD"),
    ("audit_writer", "AUDIT_WRITER_PASSWORD"),
)


def upgrade():
    conn = op.get_bind()
    for role, env_name in ROLES:
        pw = os.environ.get(env_name)
        if not pw:
            raise RuntimeError(f"{env_name} is not set")
        pw = pw.replace("'", "''")
        conn.exec_driver_sql(
            f"CREATE ROLE {role} LOGIN PASSWORD '{pw}' NOSUPERUSER NOCREATEDB NOCREATEROLE"
        )
    db = conn.exec_driver_sql("SELECT current_database()").scalar()
    conn.exec_driver_sql(f'GRANT CONNECT ON DATABASE "{db}" TO agent_ro, agent_rw, audit_writer')
    conn.exec_driver_sql(SQL.read_text())


def downgrade():
    conn = op.get_bind()
    conn.exec_driver_sql(
        "DROP VIEW IF EXISTS v_ticket_comments, v_tickets, v_app_logs, v_orders, v_users;"
        "DROP FUNCTION IF EXISTS redact_text(text)"
    )
    db = conn.exec_driver_sql("SELECT current_database()").scalar()
    for role, _ in ROLES:
        conn.exec_driver_sql(f'REVOKE ALL ON DATABASE "{db}" FROM {role}')
        conn.exec_driver_sql(f"DROP OWNED BY {role}")
        conn.exec_driver_sql(f"DROP ROLE {role}")
