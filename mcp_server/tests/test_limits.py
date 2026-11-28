"""Size and speed limits: a hostile or accidental huge value must not slow the server or flood the agent."""
import json
import time

import pytest

from governed import decorator as decorator_module
from governed.limits import MAX_CELL_CHARS, MAX_RESULT_CHARS, clip_rows
from governed.redaction import redact_text
from tests.helpers import audit_rows, call, code, last_audit_id

PATHOLOGICAL = {
    "one long word": "x" * 300_000,
    "email-like run": "a.b-" * 75_000,
    "many at-signs": "a@" * 150_000,
    "key words, no value": "password " * 40_000,
    "bearer spam": "Bearer " * 40_000,
    "token then spaces": "token" + " " * 300_000,
    "sk_ prefix spam": "sk_test_" * 40_000,
}


@pytest.mark.parametrize("name", list(PATHOLOGICAL))
def test_redaction_is_fast_on_pathological_input(name):
    started = time.monotonic()
    redact_text(PATHOLOGICAL[name])
    assert time.monotonic() - started < 1.0, name          # it was 9 s for 100k characters before the fix


def test_redaction_still_catches_what_it_should():
    out = redact_text("mail bob.smith+tag@example.co.uk, -x@y.io, token=abc123, sk_test_ABC, Bearer abc.def-1")
    for secret in ("bob.smith", "x@y.io", "abc123", "sk_test_ABC", "abc.def-1"):
        assert secret not in out


def test_clip_rows_cuts_long_text_and_says_so():
    rows, stopped, clipped = clip_rows([{"id": 1, "msg": "y" * (MAX_CELL_CHARS + 500)}])
    assert len(rows[0]["msg"]) < MAX_CELL_CHARS + 80 and "truncated 500 more characters" in rows[0]["msg"]
    assert clipped == 1 and stopped is False and rows[0]["id"] == 1


def test_clip_rows_stops_when_the_total_is_too_large():
    rows, stopped, _ = clip_rows([{"v": "z" * MAX_CELL_CHARS} for _ in range(200)])
    assert stopped and 1 <= len(rows) < 200
    assert sum(len(r["v"]) for r in rows) <= MAX_RESULT_CHARS + MAX_CELL_CHARS + 100


def test_clip_rows_always_returns_at_least_one_row():
    rows, _, _ = clip_rows([{"v": "z" * 10}], max_total=1)
    assert len(rows) == 1


@pytest.mark.db
def test_a_query_that_returns_huge_text_is_clipped_and_fast():
    from tools import telemetry
    started = time.monotonic()
    r = call(telemetry.run_readonly_sql, "bob", sql="SELECT repeat('x', 100000) AS big FROM v_app_logs LIMIT 5")
    assert r["ok"] and time.monotonic() - started < 5          # it took 47 s before the fix
    assert r["result"]["cells_clipped"] == 5 and len(json.dumps(r)) < 20_000


@pytest.mark.db
def test_the_whole_result_is_bounded_even_with_many_large_rows():
    from tools import telemetry
    r = call(telemetry.run_readonly_sql, "bob", sql="SELECT repeat('x', 1500) AS a, repeat('y', 1500) AS b FROM v_app_logs")
    assert r["ok"] and r["result"]["truncated"] and len(json.dumps(r)) < 400_000


@pytest.mark.db
def test_redaction_runs_inside_the_tool_deadline(monkeypatch):
    """A slow redaction must be cut off like any other slow part of the call."""
    import dataclasses
    from governed.config import get_settings
    from governed.decorator import governed_tool
    from governed.policy import Tier

    @governed_tool(Tier.READ, name="t_plain_read")
    def t_plain_read(reasoning: str = ""):
        return {"fine": True}

    s = dataclasses.replace(get_settings(), tool_timeout_seconds=0.3)
    monkeypatch.setattr(decorator_module, "get_settings", lambda: s)
    real = decorator_module.redact_obj
    # slow only for this tool's result, so the audit writes (which also redact) are unaffected
    monkeypatch.setattr(decorator_module, "redact_obj", lambda o: (time.sleep(1.0), o)[1] if o == {"fine": True} else real(o))
    started = time.monotonic()
    r = call(t_plain_read, "alice")
    assert code(r) == "TOOL_TIMEOUT" and time.monotonic() - started < 0.9
    time.sleep(0.9)


@pytest.mark.db
def test_huge_agent_input_is_cut_before_it_is_stored_in_the_audit_log():
    from tools import telemetry
    mark = last_audit_id()
    started = time.monotonic()
    r = call(telemetry.run_readonly_sql, "bob", sql="SELECT '" + "z" * 3_000_000 + "'", reasoning="because " + "z" * 3_000_000)
    assert code(r) == "SQL_REJECTED" and time.monotonic() - started < 5
    row = audit_rows("run_readonly_sql", after_id=mark)[0]
    assert len(row["agent_reasoning"]) <= 2100                                  # reasoning is capped
    stored = row["args"]["sql"]
    assert len(stored) < 8200 and "audit truncated" in stored                   # and so is every argument
