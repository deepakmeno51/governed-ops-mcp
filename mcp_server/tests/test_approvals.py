"""State machine tests against real Postgres. Tests that need the approval_decider or admin
passwords run only when those are set in the environment (the server container has neither, on purpose)."""
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from governed import approvals
from governed.db import connect
from governed.errors import ToolError
from governed.identity import Identity
from governed.policy import EXECUTORS


def _available(role) -> bool:
    try:
        connect(role).close()
        return True
    except Exception:
        return False


needs_db = pytest.mark.skipif(not _available("ops_executor"), reason="ops_executor not reachable")
needs_decider = pytest.mark.skipif(not (_available("ops_executor") and _available("approval_decider")),
                                   reason="approval_decider credentials not set")
REQ = "pytest-requester"


def new_request(ttl=1.0, **extra):
    row, _ = approvals.create_request(tool="t_test", args={"n": uuid.uuid4().hex}, requester=REQ,
                                      preview={"summary": "pytest request"}, ttl_minutes=ttl, **extra)
    return row


def test_hash_binds_tool_args_requester_and_expiry():
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    base = approvals.compute_args_hash("a", {"x": 1}, "alice", t)
    assert base == approvals.compute_args_hash("a", {"x": 1}, "alice", t)
    assert base != approvals.compute_args_hash("b", {"x": 1}, "alice", t)
    assert base != approvals.compute_args_hash("a", {"x": 2}, "alice", t)
    assert base != approvals.compute_args_hash("a", {"x": 1}, "mallory", t)
    assert base != approvals.compute_args_hash("a", {"x": 1}, "alice", t + timedelta(seconds=1))


@needs_db
def test_stored_hash_matches_and_detects_changes():
    row = new_request()
    assert approvals.hash_matches(row)
    assert not approvals.hash_matches({**row, "args": {"n": "tampered"}})


@needs_db
def test_executor_role_cannot_approve_or_edit():
    row = new_request()
    with connect("ops_executor") as conn, conn.cursor() as cur:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute("UPDATE approvals SET status = 'APPROVED' WHERE id = %s", (row["id"],))
    with connect("ops_executor") as conn, conn.cursor() as cur:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute("UPDATE approvals SET decided_by = 'me', decided_at = now() WHERE id = %s", (row["id"],))
    with connect("ops_executor") as conn, conn.cursor() as cur:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute("UPDATE approvals SET args = '{}'::jsonb WHERE id = %s", (row["id"],))
    with connect("ops_executor") as conn, conn.cursor() as cur:
        with pytest.raises(psycopg.errors.CheckViolation):   # PENDING -> EXECUTING skips the approval
            cur.execute("UPDATE approvals SET status = 'EXECUTING' WHERE id = %s", (row["id"],))


@needs_db
def test_cannot_create_a_pre_approved_request():
    with connect("ops_executor") as conn, conn.cursor() as cur:
        with pytest.raises(psycopg.errors.CheckViolation):
            cur.execute("INSERT INTO approvals (tool_name, args, args_hash, requester, status, decided_by, decided_at, "
                        "idempotency_key, expires_at) VALUES ('t', '{}', repeat('0', 64), 'r', 'APPROVED', 'x', now(), %s, now() + interval '1 minute')",
                        (uuid.uuid4().hex,))


@needs_db
def test_identical_request_is_deduplicated_and_key_conflicts_are_caught():
    args = {"n": uuid.uuid4().hex}
    a, d1 = approvals.create_request(tool="t_test", args=args, requester=REQ, preview={}, ttl_minutes=1)
    b, d2 = approvals.create_request(tool="t_test", args=args, requester=REQ, preview={}, ttl_minutes=1)
    assert a["id"] == b["id"] and d2 and not d1
    key = uuid.uuid4().hex
    c, _ = approvals.create_request(tool="t_test", args={"k": 1}, requester=REQ, preview={}, idempotency_key=key, ttl_minutes=1)
    d, dup = approvals.create_request(tool="t_test", args={"k": 1}, requester=REQ, preview={}, idempotency_key=key, ttl_minutes=1)
    assert c["id"] == d["id"] and dup
    with pytest.raises(ToolError) as e:
        approvals.create_request(tool="t_test", args={"k": 2}, requester=REQ, preview={}, idempotency_key=key, ttl_minutes=1)
    assert e.value.code == "IDEMPOTENCY_CONFLICT"


@needs_db
def test_pending_cannot_execute_and_only_requester_may_try():
    row = new_request()
    with pytest.raises(ToolError) as e:
        approvals.execute(str(row["id"]), Identity(REQ, "operator"))
    assert e.value.code == "APPROVAL_PENDING"
    with pytest.raises(ToolError) as e:
        approvals.execute(str(row["id"]), Identity("someone-else", "operator"))
    assert e.value.code == "PERMISSION_DENIED"


@needs_db
def test_requests_expire():
    row = new_request(ttl=0.02)   # 1.2 seconds
    time.sleep(1.6)
    st = approvals.status(str(row["id"]))
    assert st["status"] == "EXPIRED"
    with pytest.raises(ToolError) as e:
        approvals.execute(str(row["id"]), Identity(REQ, "operator"))
    assert e.value.code == "APPROVAL_EXPIRED"


def _decide(row, who, status="APPROVED"):
    with connect("approval_decider") as conn, conn.cursor() as cur:
        cur.execute("UPDATE approvals SET status = %s, decided_by = %s, decided_at = now() "
                    "WHERE id = %s AND status = 'PENDING'", (status, who, row["id"]))
        return cur.rowcount


@needs_decider
def test_full_lifecycle_runs_exactly_once():
    ran = []
    EXECUTORS["t_test"] = lambda args, row, cur: (ran.append(1), {"ran": True})[1]
    row = new_request()
    assert _decide(row, "approver-1") == 1
    assert _decide(row, "approver-2") == 0           # a second decision changes nothing
    first = approvals.execute(str(row["id"]), Identity(REQ, "operator"))
    again = approvals.execute(str(row["id"]), Identity(REQ, "operator"))
    assert first["status"] == "EXECUTED" and again["status"] == "ALREADY_EXECUTED"
    assert len(ran) == 1


@needs_decider
def test_requester_cannot_approve_own_request_and_decider_cannot_execute():
    row = new_request()
    with connect("approval_decider") as conn, conn.cursor() as cur:
        with pytest.raises(psycopg.errors.CheckViolation):
            cur.execute("UPDATE approvals SET status = 'APPROVED', decided_by = %s, decided_at = now() WHERE id = %s", (REQ, row["id"]))
    _decide(row, "approver-1")
    with connect("approval_decider") as conn, conn.cursor() as cur:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute("UPDATE approvals SET status = 'EXECUTING' WHERE id = %s", (row["id"],))


@needs_decider
def test_failed_execution_is_recorded_and_not_retried():
    def boom(args, row, cur):
        raise ToolError("DOWNSTREAM_TIMEOUT", "timed out", "check health first")
    EXECUTORS["t_test"] = boom
    row = new_request()
    _decide(row, "approver-1")
    with pytest.raises(ToolError) as e:
        approvals.execute(str(row["id"]), Identity(REQ, "operator"))
    assert e.value.code == "EXECUTION_FAILED"
    assert approvals.status(str(row["id"]))["status"] == "FAILED"
    with pytest.raises(ToolError) as e2:
        approvals.execute(str(row["id"]), Identity(REQ, "operator"))
    assert e2.value.code == "EXECUTION_FAILED"


@pytest.mark.skipif(not (_available("ops_executor") and _available("approval_decider") and os.environ.get("POSTGRES_PASSWORD")),
                    reason="needs approval_decider and admin credentials")
def test_tampered_args_are_refused_at_execution():
    EXECUTORS["t_test"] = lambda args, row, cur: {"ran": True}
    row = new_request()
    _decide(row, "approver-1")
    with psycopg.connect(host=os.environ.get("DB_HOST", "postgres"), port=os.environ.get("DB_PORT", "5432"),
                         dbname=os.environ.get("DB_NAME", "ops"), user=os.environ["POSTGRES_USER"],
                         password=os.environ["POSTGRES_PASSWORD"], autocommit=True) as admin:
        admin.execute("ALTER TABLE approvals DISABLE TRIGGER approvals_guard_trg")
        admin.execute("UPDATE approvals SET args = '{\"n\": \"evil\"}'::jsonb WHERE id = %s", (row["id"],))
        admin.execute("ALTER TABLE approvals ENABLE TRIGGER approvals_guard_trg")
    with pytest.raises(ToolError) as e:
        approvals.execute(str(row["id"]), Identity(REQ, "operator"))
    assert e.value.code == "HASH_MISMATCH"


@needs_db
def test_execution_refuses_when_more_rows_match_than_were_approved():
    from tools.remediation import exec_sql_mutation
    sql = "UPDATE tickets SET severity = 'sev3' WHERE id = 31"      # matches 1 row now
    stale_approval = {"preview": {"rows_matched": 0}}                # the approver saw 0 rows
    with connect("ops_executor") as conn, conn.cursor() as cur:
        with pytest.raises(ToolError) as e:
            exec_sql_mutation({"sql": sql}, stale_approval, cur)
    assert e.value.code == "STATE_CHANGED"
