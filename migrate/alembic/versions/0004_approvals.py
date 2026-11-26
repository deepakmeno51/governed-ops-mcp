"""approval state machine: roles ops_executor and approval_decider, preview column, transition trigger"""
import os
from pathlib import Path

from alembic import op

revision = "0004"
down_revision = "0003"

SQL = Path(__file__).resolve().parent.parent / "sql" / "0004_approvals.sql"
ROLES = (("ops_executor", "OPS_EXECUTOR_PASSWORD"), ("approval_decider", "APPROVAL_DECIDER_PASSWORD"))


def upgrade():
    conn = op.get_bind()
    for role, env_name in ROLES:
        pw = os.environ.get(env_name)
        if not pw:
            raise RuntimeError(f"{env_name} is not set")
        pw = pw.replace("'", "''")
        conn.exec_driver_sql(f"CREATE ROLE {role} LOGIN PASSWORD '{pw}' NOSUPERUSER NOCREATEDB NOCREATEROLE")
    db = conn.exec_driver_sql("SELECT current_database()").scalar()
    conn.exec_driver_sql(f'GRANT CONNECT ON DATABASE "{db}" TO ops_executor, approval_decider')
    conn.exec_driver_sql(SQL.read_text())


def downgrade():
    conn = op.get_bind()
    conn.exec_driver_sql("DROP TRIGGER IF EXISTS approvals_guard_trg ON approvals")
    conn.exec_driver_sql("DROP FUNCTION IF EXISTS approvals_guard()")
    conn.exec_driver_sql("ALTER TABLE approvals DROP CONSTRAINT IF EXISTS approvals_status_check")
    conn.exec_driver_sql("DELETE FROM approvals")
    conn.exec_driver_sql("ALTER TABLE approvals DROP COLUMN IF EXISTS preview")
    conn.exec_driver_sql(
        "ALTER TABLE approvals ADD CONSTRAINT approvals_status_check "
        "CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'EXECUTED'))")
    db = conn.exec_driver_sql("SELECT current_database()").scalar()
    for role, _ in ROLES:
        conn.exec_driver_sql(f'REVOKE ALL ON DATABASE "{db}" FROM {role}')
        conn.exec_driver_sql(f"DROP OWNED BY {role}")
        conn.exec_driver_sql(f"DROP ROLE {role}")
