"""Day 10: tool deadlines, one retry for reads, identity in worker threads, and the maintenance job."""
import dataclasses
import time

import psycopg
import pytest

from governed import approvals, maintenance
from governed import decorator as decorator_module
from governed.config import get_settings
from governed.decorator import CURRENT_IDENTITY, governed_tool
from governed.policy import EXECUTORS, Tier
from tests.helpers import audit_rows, call, code, decide, last_audit_id, new_request

pytestmark = pytest.mark.db

CALLS: dict = {"n": 0}


@pytest.fixture(autouse=True)
def _reset():
    CALLS["n"] = 0


@pytest.fixture
def short_deadline(monkeypatch):
    """Give Tier 1 and 2 tools a 0.3 second deadline."""
    s = dataclasses.replace(get_settings(), tool_timeout_seconds=0.3)
    monkeypatch.setattr(decorator_module, "get_settings", lambda: s)


@governed_tool(Tier.READ, name="t_slow_read")
def t_slow_read(reasoning: str = ""):
    time.sleep(1.2)
    return {"done": True}


@governed_tool(Tier.LOW_WRITE, name="t_slow_write")
def t_slow_write(reasoning: str = ""):
    time.sleep(1.2)
    return {"done": True}


@governed_tool(Tier.READ, name="t_whoami")
def t_whoami(reasoning: str = ""):
    ident = CURRENT_IDENTITY.get()
    return {"actor": ident.actor, "role": ident.role}


@governed_tool(Tier.READ, name="t_flaky_read")
def t_flaky_read(reasoning: str = ""):
    CALLS["n"] += 1
    if CALLS["n"] == 1:
        raise psycopg.OperationalError("connection dropped")
    return {"calls": CALLS["n"]}


@governed_tool(Tier.READ, name="t_dead_read")
def t_dead_read(reasoning: str = ""):
    CALLS["n"] += 1
    raise psycopg.OperationalError("database is down")


@governed_tool(Tier.LOW_WRITE, name="t_flaky_write")
def t_flaky_write(reasoning: str = ""):
    CALLS["n"] += 1
    raise psycopg.OperationalError("connection dropped")


def test_slow_read_is_abandoned_at_the_deadline_and_audited(short_deadline):
    mark = last_audit_id()
    t0 = time.monotonic()
    r = call(t_slow_read, "alice")
    assert time.monotonic() - t0 < 1.0                       # we did not wait for the 1.2 s body
    assert code(r) == "TOOL_TIMEOUT" and r["error"]["retryable"] is True
    assert audit_rows("t_slow_read", after_id=mark)[-1]["outcome"] == "ERROR:TOOL_TIMEOUT"
    time.sleep(1.1)                                          # let the abandoned thread finish


def test_slow_write_timeout_warns_it_may_have_completed_and_is_not_retryable(short_deadline):
    r = call(t_slow_write, "alice")
    assert code(r) == "TOOL_TIMEOUT" and r["error"]["retryable"] is False
    assert "may still have completed" in r["error"]["hint"]
    time.sleep(1.1)


def test_fast_calls_are_not_affected_by_the_deadline(short_deadline):
    assert call(t_whoami, "alice")["ok"]


def test_the_caller_identity_reaches_the_worker_thread():
    assert call(t_whoami, "alice")["result"] == {"actor": "alice", "role": "operator"}
    assert call(t_whoami, "bob")["result"] == {"actor": "bob", "role": "viewer"}


def test_a_read_is_retried_once_when_the_database_drops_the_connection():
    mark = last_audit_id()
    r = call(t_flaky_read, "bob")
    assert r["ok"] and r["result"]["calls"] == 2
    assert audit_rows("t_flaky_read", after_id=mark)[-1]["args"]["attempts"] == 2


def test_a_read_gives_up_after_one_retry():
    r = call(t_dead_read, "bob")
    assert code(r) == "DB_UNAVAILABLE" and r["error"]["retryable"] is True and CALLS["n"] == 2


def test_a_write_is_never_retried_automatically():
    r = call(t_flaky_write, "alice")
    assert code(r) == "DB_UNAVAILABLE" and CALLS["n"] == 1


def test_a_tier3_execution_is_not_abandoned_by_the_tool_deadline(short_deadline):
    """Abandoning a half-finished destructive action would leave its outcome unknown, so it runs to completion."""
    from tools import remediation
    EXECUTORS["t_slow_exec"] = lambda args, row, cur: (time.sleep(0.8), {"finished": True})[1]
    row = new_request(tool="t_slow_exec", requester="alice")
    assert decide(row) == 1
    r = call(remediation.execute_approved_action, "alice", approval_id=str(row["id"]))
    assert r["ok"] and r["result"]["status"] == "EXECUTED" and r["result"]["result"] == {"finished": True}


def test_the_maintenance_job_expires_requests_and_audits_it():
    row = new_request(ttl=0.02)
    time.sleep(1.6)
    mark = last_audit_id()
    out = maintenance.run_once()
    assert str(row["id"]) in out["expired"]
    assert approvals.get_row(str(row["id"]))["status"] == "EXPIRED"
    ev = audit_rows(event_type="APPROVAL_EXPIRED", after_id=mark, approval_id=row["id"])
    assert len(ev) == 1 and ev[0]["actor"] == "system"
    assert str(row["id"]) not in maintenance.run_once()["expired"]       # a second pass changes nothing


def test_the_maintenance_job_survives_a_failing_pass(monkeypatch):
    def boom():
        raise psycopg.OperationalError("db down")
    monkeypatch.setattr(approvals, "expire_stale", boom)
    out = maintenance.run_once()
    assert out == {"error": "OperationalError"} and maintenance.STATE["last_error"] == "OperationalError"


def test_the_background_thread_runs_the_job_on_a_timer(monkeypatch):
    s = dataclasses.replace(get_settings(), maintenance_interval_seconds=0.2)
    monkeypatch.setattr(maintenance, "get_settings", lambda: s)
    row = new_request(ttl=0.02)
    stop = maintenance.start_background()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and approvals.get_row(str(row["id"]))["status"] != "EXPIRED":
            time.sleep(0.2)
        assert approvals.get_row(str(row["id"]))["status"] == "EXPIRED"
    finally:
        stop.set()
