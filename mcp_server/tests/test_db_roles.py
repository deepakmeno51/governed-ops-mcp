"""What each database role can and cannot do. These are the last line of defence: they hold even if the
SQL guard or the application code has a bug, so they are tested directly against real Postgres."""
import psycopg
import pytest

from governed.db import connect

pytestmark = pytest.mark.db

DENIED = (psycopg.errors.InsufficientPrivilege, psycopg.errors.ReadOnlySqlTransaction, psycopg.errors.CheckViolation,
          psycopg.errors.RaiseException)


def _runs(role: str, sql: str) -> bool:
    """True if the statement is accepted. Anything that changed data is rolled back."""
    with connect(role) as conn, conn.cursor() as cur:
        try:
            cur.execute(sql)
            return True
        except DENIED:
            return False
        finally:
            conn.rollback()


@pytest.mark.parametrize("sql", [
    "SELECT count(*) FROM v_orders",
    "SELECT count(*) FROM v_tickets",
    "SELECT count(*) FROM v_app_logs",
])
def test_agent_ro_reads_the_redacted_views(sql):
    assert _runs("agent_ro", sql)


@pytest.mark.parametrize("sql", [
    "SELECT * FROM orders", "SELECT * FROM users", "SELECT * FROM app_logs", "SELECT * FROM approvals",
    "SELECT * FROM audit_events", "SELECT pg_read_file('/etc/passwd')", "SELECT lo_import('/etc/passwd')",
    "UPDATE orders SET status = 'failed' WHERE id = 1", "DELETE FROM orders WHERE id = 1",
    "INSERT INTO ticket_comments (ticket_id, author, body) VALUES (31, 'x', 'y')",
    "CREATE TABLE evil (id int)", "DROP TABLE orders",
])
def test_agent_ro_cannot_touch_raw_tables_files_or_write(sql):
    assert not _runs("agent_ro", sql)


def test_agent_ro_is_read_only_with_a_short_statement_timeout():
    with connect("agent_ro") as conn, conn.cursor() as cur:
        cur.execute("SHOW default_transaction_read_only")
        assert cur.fetchone()["default_transaction_read_only"] == "on"
        cur.execute("SHOW statement_timeout")
        assert cur.fetchone()["statement_timeout"] == "5s"


def test_agent_ro_slow_queries_are_cancelled():
    with connect("agent_ro") as conn, conn.cursor() as cur:
        with pytest.raises(psycopg.errors.QueryCanceled):
            cur.execute("SELECT pg_sleep(8)")


@pytest.mark.parametrize("sql", [
    "UPDATE orders SET status = 'pending' WHERE id = 1",
    "UPDATE tickets SET status = 'investigating' WHERE id = 31",
    "UPDATE tickets SET severity = 'sev2' WHERE id = 31",
    "INSERT INTO ticket_comments (ticket_id, author, body) VALUES (31, 'pytest', 'ok')",
    "SELECT count(*) FROM orders",
])
def test_agent_rw_can_do_exactly_what_the_guard_allows(sql):
    assert _runs("agent_rw", sql)


@pytest.mark.parametrize("sql", [
    "UPDATE orders SET total_cents = 0 WHERE id = 1",          # column-level grant (migration 0006)
    "UPDATE orders SET user_id = 1 WHERE id = 1",
    "UPDATE orders SET updated_at = now() WHERE id = 1",
    "UPDATE tickets SET title = 'changed' WHERE id = 31",
    "UPDATE tickets SET description = 'changed' WHERE id = 31",
    "UPDATE ticket_comments SET body = 'rewritten'",
    "DELETE FROM orders WHERE id = 1", "DELETE FROM tickets WHERE id = 31", "DELETE FROM ticket_comments",
    "SELECT * FROM users", "SELECT * FROM audit_events", "SELECT * FROM approvals",
    "INSERT INTO audit_events (actor, event_type) VALUES ('x', 'y')",
    "INSERT INTO approvals (tool_name) VALUES ('x')",
    "CREATE TABLE evil (id int)", "TRUNCATE orders",
])
def test_agent_rw_cannot_go_beyond_that(sql):
    assert not _runs("agent_rw", sql)


@pytest.mark.parametrize("sql", [
    "UPDATE audit_events SET actor = 'mallory'", "DELETE FROM audit_events", "TRUNCATE audit_events",
    "SELECT * FROM orders", "SELECT * FROM users", "SELECT * FROM approvals",
    "UPDATE approvals SET status = 'APPROVED'", "CREATE TABLE evil (id int)",
])
def test_audit_writer_can_only_append_and_read_the_log(sql):
    assert not _runs("audit_writer", sql)


@pytest.mark.parametrize("sql", [
    "SELECT * FROM audit_events", "INSERT INTO audit_events (actor, event_type) VALUES ('x', 'y')",
    "SELECT * FROM users", "SELECT * FROM orders", "DELETE FROM approvals",
    "UPDATE approvals SET args = '{}'::jsonb", "UPDATE approvals SET decided_by = 'me'",
    "CREATE TABLE evil (id int)",       # (it may INSERT requests: that is how Tier 3 tools ask for approval)
])
def test_ops_executor_cannot_read_the_log_edit_requests_or_decide(sql):
    assert not _runs("ops_executor", sql)


@pytest.mark.parametrize("sql", [
    "INSERT INTO approvals (tool_name, args, args_hash, requester, idempotency_key, expires_at) "
    "VALUES ('x', '{}', repeat('0', 64), 'r', 'k', now())",
    "UPDATE approvals SET args = '{}'::jsonb", "UPDATE approvals SET status = 'EXECUTING'",
    "UPDATE approvals SET started_at = now()", "DELETE FROM approvals",
    "SELECT * FROM audit_events", "SELECT * FROM orders", "SELECT * FROM users", "CREATE TABLE evil (id int)",
])
def test_approval_decider_can_decide_but_not_create_edit_or_execute(sql):
    assert not _runs("approval_decider", sql)


def test_no_application_role_can_disable_the_audit_triggers():
    for role in ("agent_ro", "agent_rw", "audit_writer", "ops_executor", "approval_decider"):
        assert not _runs(role, "ALTER TABLE audit_events DISABLE TRIGGER USER"), role
        assert not _runs(role, "ALTER TABLE approvals DISABLE TRIGGER USER"), role
