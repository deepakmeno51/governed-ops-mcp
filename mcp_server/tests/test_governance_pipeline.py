"""The governance pipeline end to end, in-process, against the isolated test database:
identity -> role check -> tier gate -> audit -> run -> redact -> audit."""
import json

import pytest

from governed import audit
from governed.db import connect
from governed.decorator import governed_tool
from governed.policy import Tier
from tests.helpers import audit_rows, call, code, last_audit_id
from tools import telemetry, tickets

pytestmark = pytest.mark.db

STATE: dict = {"ran": [], "saw_started": [], "mark": 0}


@governed_tool(Tier.READ, name="t_probe")
def t_probe(reasoning: str = ""):
    with connect("audit_writer") as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM audit_events WHERE tool_name = 't_probe' AND outcome = 'STARTED' AND id > %s",
                    (STATE["mark"],))
        STATE["saw_started"].append(cur.fetchone()["n"])
    return {"ok": True}


@governed_tool(Tier.LOW_WRITE, name="t_write")
def t_write(reasoning: str = ""):
    STATE["ran"].append("t_write")
    return {"wrote": True}


@governed_tool(Tier.DESTRUCTIVE, name="t_destructive")
def t_destructive(reasoning: str = ""):
    STATE["ran"].append("t_destructive")
    return {"destroyed": True}


@governed_tool(Tier.READ, name="t_secret_out")
def t_secret_out(reasoning: str = ""):
    return {"note": "login failed, password=hunter2 for bob@example.com", "api_key": "sk_test_ABC123"}


@governed_tool(Tier.READ, name="t_boom")
def t_boom(reasoning: str = ""):
    raise ValueError("internal detail from /app/secret_module.py line 12")


@pytest.fixture(autouse=True)
def _reset():
    STATE["ran"].clear()
    STATE["saw_started"].clear()


def test_viewer_is_denied_a_write_and_it_is_logged():
    mark = last_audit_id()
    r = call(tickets.add_ticket_comment, "bob", ticket_id=31, body="viewer attempt")
    assert code(r) == "PERMISSION_DENIED"
    rows = audit_rows("add_ticket_comment", after_id=mark)
    assert [x["event_type"] for x in rows] == ["TOOL_DENIED"] and rows[0]["outcome"].startswith("RBAC")
    with connect("agent_rw") as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM ticket_comments WHERE body = 'viewer attempt'")
        assert cur.fetchone()["n"] == 0


@pytest.mark.parametrize("token", [None, "wrong-token", ""])
def test_missing_or_bad_credentials_are_refused_and_logged(token):
    mark = last_audit_id()
    r = call(telemetry.search_logs, token=token)
    assert code(r) == "UNAUTHENTICATED"
    rows = audit_rows("search_logs", after_id=mark)
    assert rows and rows[0]["actor"] == "anonymous" and rows[0]["event_type"] == "TOOL_DENIED"


def test_destructive_tool_without_an_approval_path_fails_closed():
    mark = last_audit_id()
    r = call(t_destructive, "alice")
    assert code(r) == "APPROVAL_REQUIRED" and STATE["ran"] == []
    assert audit_rows("t_destructive", after_id=mark)[0]["outcome"] == "APPROVAL_REQUIRED"


def test_viewer_cannot_even_request_a_destructive_tool():
    assert code(call(t_destructive, "bob")) == "PERMISSION_DENIED" and STATE["ran"] == []


def test_audit_is_written_before_the_action_and_again_after():
    mark = STATE["mark"] = last_audit_id()
    assert call(t_probe, "alice", reasoning="check order").get("ok")
    rows = audit_rows("t_probe", after_id=mark)
    assert [(x["event_type"], x["outcome"]) for x in rows] == [("TOOL_CALL", "STARTED"), ("TOOL_RESULT", "OK")]
    assert STATE["saw_started"] == [1]       # the STARTED row already existed while the tool body ran
    assert rows[0]["agent_reasoning"] == "check order" and rows[1]["args"]["call_audit_id"] == rows[0]["id"]


def test_no_audit_record_means_no_action(monkeypatch):
    def broken(**_):
        raise RuntimeError("audit database down")
    monkeypatch.setattr(audit, "write_event", broken)
    r = call(t_write, "alice")
    assert code(r) == "AUDIT_UNAVAILABLE" and r["error"]["retryable"] is True
    assert STATE["ran"] == []


def test_audit_failure_after_the_action_is_flagged_not_hidden(monkeypatch):
    real, n = audit.write_event, {"calls": 0}

    def flaky(**kw):
        n["calls"] += 1
        if n["calls"] >= 2:
            raise RuntimeError("audit database went away")
        return real(**kw)
    monkeypatch.setattr(audit, "write_event", flaky)
    r = call(t_write, "alice")
    assert r["ok"] and "audit_warning" in r and STATE["ran"] == ["t_write"]


def test_output_is_redacted_in_the_response_and_in_the_audit_log():
    mark = last_audit_id()
    r = call(t_secret_out, "bob")
    text = json.dumps(r)
    assert "hunter2" not in text and "bob@example.com" not in text and "sk_test_ABC123" not in text
    stored = json.dumps([x["output"] for x in audit_rows("t_secret_out", after_id=mark)])
    assert "hunter2" not in stored and "sk_test_ABC123" not in stored


def test_secrets_the_agent_pastes_into_arguments_never_reach_the_audit_log():
    mark = last_audit_id()
    r = call(tickets.add_ticket_comment, "alice", ticket_id=31, body="saw token=abc123SECRETVALUE in the logs",
             reasoning="found password=hunter2 in a log line")
    assert r["ok"]
    blob = json.dumps([(x["args"], x["agent_reasoning"], x["output"]) for x in audit_rows("add_ticket_comment", after_id=mark)])
    assert "abc123SECRETVALUE" not in blob and "hunter2" not in blob and "[REDACTED" in blob
    with connect("agent_rw") as conn, conn.cursor() as cur:      # and the saved comment is redacted too
        cur.execute("SELECT body FROM ticket_comments WHERE id = %s", (r["result"]["comment_id"],))
        assert "abc123SECRETVALUE" not in cur.fetchone()["body"]


def test_unexpected_errors_return_an_id_and_no_internals():
    r = call(t_boom, "alice")
    assert code(r) == "INTERNAL_ERROR" and r["error"]["error_id"]
    text = json.dumps(r)
    assert "secret_module" not in text and "Traceback" not in text and "ValueError" not in text


def test_errors_have_code_message_hint_and_retryable():
    r = call(tickets.get_ticket, "bob", ticket_id=999999)
    assert code(r) == "NOT_FOUND" and {"code", "message", "hint", "retryable"} <= set(r["error"])


def test_sql_guard_rejection_is_audited_as_an_error():
    mark = last_audit_id()
    r = call(telemetry.run_readonly_sql, "bob", sql="DROP TABLE orders")
    assert code(r) == "SQL_REJECTED"
    assert audit_rows("run_readonly_sql", after_id=mark)[-1]["outcome"] == "ERROR:SQL_REJECTED"


def test_log_search_results_are_redacted():
    r = call(telemetry.search_logs, "bob", contains="api_key", since_minutes=10080)
    text = json.dumps(r)
    assert r["ok"] and "sk_test" not in text and "[REDACTED" in text


def test_the_chain_still_verifies_after_all_of_this():
    assert audit.verify_chain()["ok"]
