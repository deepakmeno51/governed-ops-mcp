"""approvals.started_at plus guard-trigger rules so crashed executions can be detected and closed out"""
import re
from pathlib import Path

from alembic import op

revision = "0005"
down_revision = "0004"

SQL_DIR = Path(__file__).resolve().parent.parent / "sql"


def upgrade():
    op.get_bind().exec_driver_sql((SQL_DIR / "0005_execution_recovery.sql").read_text())


def downgrade():
    conn = op.get_bind()
    # Restore the Day 6-9 version of the guard function, then drop the column.
    old = (SQL_DIR / "0004_approvals.sql").read_text()
    fn = re.search(r"CREATE FUNCTION approvals_guard\(\).*?\n\$f\$;\n", old, re.S).group(0)
    conn.exec_driver_sql(fn.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION"))
    conn.exec_driver_sql("REVOKE UPDATE (started_at) ON approvals FROM ops_executor")
    conn.exec_driver_sql("ALTER TABLE approvals DROP COLUMN started_at")
