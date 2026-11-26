"""One connection per database role. Each role has the minimum privileges (see migrations)."""
import psycopg
from psycopg.rows import dict_row

from .config import get_settings

ROLES = ("agent_ro", "agent_rw", "audit_writer", "ops_executor", "approval_decider")


def connect(role: str) -> psycopg.Connection:
    s = get_settings()
    passwords = {
        "agent_ro": s.ro_password,
        "agent_rw": s.rw_password,
        "audit_writer": s.audit_password,
        "ops_executor": s.executor_password,
        "approval_decider": s.decider_password,
    }
    if role not in passwords:
        raise ValueError(f"unknown database role: {role}")
    conn = psycopg.connect(
        host=s.db_host,
        port=s.db_port,
        dbname=s.db_name,
        user=role,
        password=passwords[role],
        connect_timeout=3,
        row_factory=dict_row,
    )
    if role == "agent_ro":
        conn.read_only = True
    return conn
