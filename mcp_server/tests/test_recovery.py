"""Day 10: an execution that never finishes is detected and closed, and a lost claim never leaves a change behind."""
import psycopg
import pytest

from governed import approvals
from governed.db import connect
from governed.errors import ToolError
from governed.identity import Identity
from governed.policy import ATOMIC_EXECUTORS, EXECUTORS
from tests.helpers import REQ, audit_rows, claim, decide, last_audit_id, new_request, status_of

pytestmark = pytest.mark.db


def _approved(tool="t_test"):
    row = new_request(tool=tool)
    assert decide(row) == 1
    return row


def test_a_stale_execution_is_closed_as_unknown_for_a_non_atomic_tool():
    row = _approved()
    claim(row, started_seconds_ago=300)
    mark = last_audit_id()
    assert str(row["id"]) in approvals.recover_stuck_executions(stale_seconds=60)
    done = status_of(row)
    assert done["status"] == "FAILED" and done["executed_at"] is not None
    assert done["result"]["error"]["code"] == "EXECUTION_ABANDONED" and done["result"]["error"]["outcome"] == "UNKNOWN"
    ev = audit_rows(event_type="APPROVAL_EXECUTION_ABANDONED", after_id=mark, approval_id=row["id"])
    assert len(ev) == 1 and ev[0]["actor"] == "system"


def test_a_stale_atomic_execution_is_reported_as_not_applied():
    ATOMIC_EXECUTORS.add("t_atomic")
    row = _approved("t_atomic")
    claim(row, started_seconds_ago=300)
    approvals.recover_stuck_executions(stale_seconds=60)
    assert status_of(row)["result"]["error"]["outcome"] == "NOT_APPLIED"


def test_a_fresh_execution_is_left_alone():
    row = _approved()
    claim(row, started_seconds_ago=1)
    assert str(row["id"]) not in approvals.recover_stuck_executions(stale_seconds=60)
    assert status_of(row)["status"] == "EXECUTING"


def test_a_row_a_live_executor_holds_is_skipped():
    row = _approved()
    claim(row, started_seconds_ago=300)
    with connect("ops_executor") as holder, holder.cursor() as cur:
        cur.execute("SELECT id FROM approvals WHERE id = %s FOR UPDATE", (row["id"],))     # an executor mid-run
        assert str(row["id"]) not in approvals.recover_stuck_executions(stale_seconds=60)
    assert status_of(row)["status"] == "EXECUTING"
    assert str(row["id"]) in approvals.recover_stuck_executions(stale_seconds=60)      # once released, it is closed


def test_execute_reports_in_progress_then_failed_after_recovery():
    row = _approved()
    claim(row, started_seconds_ago=300)
    caller = Identity(REQ, "operator")
    with pytest.raises(ToolError) as e:
        approvals.execute(str(row["id"]), caller)
    assert e.value.code == "EXECUTION_IN_PROGRESS"
    approvals.recover_stuck_executions(stale_seconds=60)
    with pytest.raises(ToolError) as e:
        approvals.execute(str(row["id"]), caller)
    assert e.value.code == "EXECUTION_FAILED"


def test_a_lost_claim_rolls_the_change_back():
    """If recovery (or anything else) ends the approval while the executor is mid-run, the executor's
    change must not be committed behind a FAILED approval."""
    def sneaky(args, row, cur):
        cur.execute("SET LOCAL ROLE agent_rw")
        cur.execute("INSERT INTO ticket_comments (ticket_id, author, body) VALUES (31, 'lost-claim-test', 'must roll back')")
        cur.execute("RESET ROLE")
        cur.execute("UPDATE approvals SET status = 'FAILED', executed_at = now(), result = '{}'::jsonb WHERE id = %s", (row["id"],))
        return {"ran": True}
    def comment_count():
        with connect("agent_rw") as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM ticket_comments WHERE author = 'lost-claim-test'")
            return cur.fetchone()["n"]

    EXECUTORS["t_test"] = sneaky
    row = _approved()
    before = comment_count()
    with pytest.raises(ToolError) as e:
        approvals.execute(str(row["id"]), Identity(REQ, "operator"))
    assert e.value.code == "EXECUTION_FAILED" and "Rolled back" in e.value.message
    assert comment_count() == before
    assert status_of(row)["status"] == "FAILED"


def test_a_failed_execution_is_never_marked_retryable():
    def timeout(args, row, cur):
        raise ToolError("DOWNSTREAM_TIMEOUT", "timed out", "check health", True)    # retryable underneath
    EXECUTORS["t_test"] = timeout
    row = _approved()
    with pytest.raises(ToolError) as e:
        approvals.execute(str(row["id"]), Identity(REQ, "operator"))
    assert e.value.code == "EXECUTION_FAILED" and e.value.retryable is False
    assert "request a new one" in e.value.hint


def test_started_at_is_guarded_by_the_database():
    row = new_request()
    with connect("ops_executor") as conn, conn.cursor() as cur:                       # not settable on a pending row
        with pytest.raises(psycopg.errors.CheckViolation):
            cur.execute("UPDATE approvals SET started_at = now() WHERE id = %s", (row["id"],))
    with connect("ops_executor") as conn, conn.cursor() as cur:                       # not settable at creation
        with pytest.raises(psycopg.errors.CheckViolation):
            cur.execute("INSERT INTO approvals (tool_name, args, args_hash, requester, idempotency_key, expires_at, started_at) "
                        "VALUES ('t', '{}', repeat('0', 64), 'r', gen_random_uuid()::text, now() + interval '1 minute', now())")
    decide(row)
    with connect("ops_executor") as conn, conn.cursor() as cur:                       # a claim must stamp it
        with pytest.raises(psycopg.errors.CheckViolation):
            cur.execute("UPDATE approvals SET status = 'EXECUTING' WHERE id = %s", (row["id"],))
    claim(row)
    with connect("ops_executor") as conn, conn.cursor() as cur:                       # and it cannot move afterwards
        with pytest.raises(psycopg.errors.CheckViolation):
            cur.execute("UPDATE approvals SET started_at = now() - interval '1 hour' WHERE id = %s", (row["id"],))
    with connect("approval_decider") as conn, conn.cursor() as cur:                   # the UI role has no access to it
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute("UPDATE approvals SET started_at = now() WHERE id = %s", (row["id"],))
