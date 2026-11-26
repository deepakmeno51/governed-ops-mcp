"""Append-only, hash-chained audit log.

row_hash = sha256(prev_hash + canonical_json(event fields)). Editing or deleting any row
breaks every hash after it, and verify_chain() finds the first break.
Database triggers also block UPDATE, DELETE and TRUNCATE (migration 0003).
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from psycopg.types.json import Jsonb

from .db import connect

GENESIS = "0" * 64
_LOCK_KEY = 7_270_001  # advisory lock so concurrent writers cannot fork the chain


def jsonable(value: Any) -> Any:
    """Round-trip through JSON so the hashed value equals what Postgres jsonb returns."""
    if value is None:
        return None
    text = json.dumps(value, default=str, ensure_ascii=False).replace("\\u0000", "")
    return json.loads(text)


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _ts(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat(timespec="microseconds")


def compute_hash(prev_hash: str, payload: dict) -> str:
    return hashlib.sha256((prev_hash + canonical(payload)).encode()).hexdigest()


def _payload(ts, actor, event_type, tool_name, risk_tier, args, reasoning, approval_id, outcome, output) -> dict:
    return {
        "ts": _ts(ts),
        "actor": actor,
        "event_type": event_type,
        "tool_name": tool_name,
        "risk_tier": risk_tier,
        "args": args,
        "agent_reasoning": reasoning,
        "approval_id": str(approval_id) if approval_id else None,
        "outcome": outcome,
        "output": output,
    }


def write_event(*, actor: str, event_type: str, tool_name: str | None = None, risk_tier: int | None = None,
                args: Any = None, agent_reasoning: str | None = None, approval_id=None,
                outcome: str | None = None, output: Any = None) -> int:
    ts = datetime.now(timezone.utc)
    args_j, out_j = jsonable(args), jsonable(output)
    reasoning = agent_reasoning[:2000] if agent_reasoning else None
    with connect("audit_writer") as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (_LOCK_KEY,))
            cur.execute("SELECT row_hash FROM audit_events ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            prev = row["row_hash"] if row else GENESIS
            payload = _payload(ts, actor, event_type, tool_name, risk_tier, args_j, reasoning,
                               approval_id, outcome, out_j)
            row_hash = compute_hash(prev, payload)
            cur.execute(
                """INSERT INTO audit_events
                   (ts, actor, event_type, tool_name, risk_tier, args, agent_reasoning,
                    approval_id, outcome, output, prev_hash, row_hash)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                (ts, actor, event_type, tool_name, risk_tier,
                 Jsonb(args_j) if args_j is not None else None, reasoning, approval_id, outcome,
                 Jsonb(out_j) if out_j is not None else None, prev, row_hash),
            )
            return cur.fetchone()["id"]


def verify_chain() -> dict:
    """Recompute every hash in order. Returns {ok, checked, first_bad_id, reason}."""
    prev = GENESIS
    checked = 0
    with connect("audit_writer") as conn:
        with conn.cursor(name="audit_scan") as cur:
            cur.execute("SELECT * FROM audit_events ORDER BY id")
            for r in cur:
                payload = _payload(r["ts"], r["actor"], r["event_type"], r["tool_name"], r["risk_tier"],
                                   r["args"], r["agent_reasoning"], r["approval_id"], r["outcome"], r["output"])
                if r["prev_hash"] != prev:
                    return {"ok": False, "checked": checked, "first_bad_id": r["id"],
                            "reason": "prev_hash does not match the previous row (row removed or reordered)"}
                if compute_hash(prev, payload) != r["row_hash"]:
                    return {"ok": False, "checked": checked, "first_bad_id": r["id"],
                            "reason": "row contents do not match row_hash (row edited)"}
                prev = r["row_hash"]
                checked += 1
    return {"ok": True, "checked": checked, "first_bad_id": None, "reason": ""}
