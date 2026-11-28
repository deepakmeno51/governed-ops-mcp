"""Approval requests and their state machine.

PENDING -> APPROVED | REJECTED | EXPIRED        (a human decides, or time runs out)
APPROVED -> EXECUTING -> EXECUTED | FAILED      (claimed once, then finished)

The database trigger (migration 0004) enforces which role may make which move.
This module adds hash binding, idempotency, expiry handling and the execution path.
"""
import hashlib
import uuid
from datetime import datetime, timezone

from psycopg.types.json import Jsonb

from . import audit
from .audit import canonical, jsonable
from .config import get_settings
from .db import connect
from .errors import ToolError, from_exception
from .policy import ATOMIC_EXECUTORS, EXECUTORS

LIVE = ("PENDING", "APPROVED", "EXECUTING")


# ---- hash binding -----------------------------------------------------------
def compute_args_hash(tool: str, args: dict, requester: str, expires_at: datetime) -> str:
    """SHA-256 over tool name, arguments, requester and expiry. Changing any of them changes the hash."""
    payload = {
        "tool": tool,
        "args": jsonable(args),
        "requester": requester,
        "expires_at": expires_at.astimezone(timezone.utc).isoformat(timespec="microseconds"),
    }
    return hashlib.sha256(canonical(payload).encode()).hexdigest()


def hash_matches(row: dict) -> bool:
    return compute_args_hash(row["tool_name"], row["args"], row["requester"], row["expires_at"]) == row["args_hash"]


def public_view(row: dict) -> dict:
    """The fields an agent may see."""
    iso = lambda v: v.isoformat() if v else None  # noqa: E731
    return {
        "approval_id": str(row["id"]),
        "tool": row["tool_name"],
        "status": row["status"],
        "requester": row["requester"],
        "args": row["args"],
        "args_hash": row["args_hash"],
        "created_at": iso(row["created_at"]),
        "expires_at": iso(row["expires_at"]),
        "decided_by": row["decided_by"],
        "decided_at": iso(row["decided_at"]),
        "executed_at": iso(row["executed_at"]),
        "result": row["result"],
        "summary": (row.get("preview") or {}).get("summary"),
    }


def _uuid(approval_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(approval_id))
    except ValueError:
        raise ToolError("INVALID_ARGUMENT", "approval_id must be a UUID.", "Use the approval_id from the request response.")


def get_row(approval_id: str, role: str = "ops_executor") -> dict | None:
    with connect(role) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM approvals WHERE id = %s", (_uuid(approval_id),))
        return cur.fetchone()


# ---- expiry -----------------------------------------------------------------
def expire_stale(role: str = "ops_executor") -> list[str]:
    with connect(role) as conn, conn.cursor() as cur:
        cur.execute("UPDATE approvals SET status = 'EXPIRED' "
                    "WHERE status IN ('PENDING', 'APPROVED') AND expires_at <= now() RETURNING id")
        ids = [str(r["id"]) for r in cur.fetchall()]
    for i in ids:
        try:
            audit.write_event(actor="system", event_type="APPROVAL_EXPIRED", approval_id=i, outcome="EXPIRED")
        except Exception:  # noqa: BLE001
            pass
    return ids


def _abandoned_result(tool: str, stale_seconds: float) -> dict:
    if tool in ATOMIC_EXECUTORS:
        err = {"code": "EXECUTION_ABANDONED", "outcome": "NOT_APPLIED",
               "message": "The server stopped while running this action. The change runs in one database transaction "
                          "that never committed, so nothing was changed.",
               "hint": "Request a new approval if the change is still needed."}
    else:
        err = {"code": "EXECUTION_ABANDONED", "outcome": "UNKNOWN",
               "message": f"The server stopped while running this action (no result after {int(stale_seconds)}s). "
                          "The action may or may not have happened.",
               "hint": "Check the system state before requesting this again."}
    return {"error": err}


def recover_stuck_executions(stale_seconds: float | None = None, role: str = "ops_executor") -> list[str]:
    """Close executions that have been EXECUTING for too long (the executor crashed or lost its connection).
    The database allows only ops_executor to do this. Rows that a live executor holds locked are skipped."""
    stale = stale_seconds if stale_seconds is not None else get_settings().execution_stale_seconds
    done: list[tuple[str, str, str]] = []
    with connect(role) as conn, conn.cursor() as cur:
        cur.execute("SELECT id, tool_name FROM approvals WHERE status = 'EXECUTING' "
                    "AND COALESCE(started_at, created_at) < now() - make_interval(secs => %s) "
                    "FOR UPDATE SKIP LOCKED", (stale,))
        for r in cur.fetchall():
            result = _abandoned_result(r["tool_name"], stale)
            cur.execute("UPDATE approvals SET status = 'FAILED', executed_at = now(), result = %s "
                        "WHERE id = %s AND status = 'EXECUTING'", (Jsonb(jsonable(result)), r["id"]))
            done.append((str(r["id"]), r["tool_name"], result["error"]["outcome"]))
    for approval_id, tool, outcome in done:
        try:
            audit.write_event(actor="system", event_type="APPROVAL_EXECUTION_ABANDONED", tool_name=tool,
                              approval_id=approval_id, outcome="FAILED:EXECUTION_ABANDONED", output={"outcome": outcome})
        except Exception:  # noqa: BLE001
            pass
    return [d[0] for d in done]


# ---- request ----------------------------------------------------------------
def create_request(*, tool: str, args: dict, requester: str, preview: dict,
                   idempotency_key: str | None = None, ttl_minutes: float | None = None) -> tuple[dict, bool]:
    """Create a PENDING approval. Returns (row, deduplicated)."""
    s = get_settings()
    ttl = ttl_minutes if ttl_minutes is not None else s.approval_ttl_minutes
    args = jsonable(args)
    with connect("ops_executor") as conn, conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"{requester}|{tool}|{canonical(args)}",))
        if idempotency_key:
            key = f"{requester}:{idempotency_key}"
            cur.execute("SELECT * FROM approvals WHERE idempotency_key = %s", (key,))
            existing = cur.fetchone()
            if existing:
                if existing["tool_name"] != tool or existing["args"] != args:
                    raise ToolError("IDEMPOTENCY_CONFLICT", "That idempotency_key was already used for a different request.",
                                    "Use a new idempotency_key for a different action.")
                return existing, True
        else:
            key = f"auto:{uuid.uuid4().hex}"
            cur.execute("SELECT * FROM approvals WHERE requester = %s AND tool_name = %s AND args = %s "
                        "AND status IN ('PENDING', 'APPROVED', 'EXECUTING') AND expires_at > now() "
                        "ORDER BY created_at DESC LIMIT 1", (requester, tool, Jsonb(args)))
            existing = cur.fetchone()
            if existing:
                return existing, True
        cur.execute("SELECT now() AS created, now() + make_interval(secs => %s) AS expires", (ttl * 60,))
        t = cur.fetchone()
        args_hash = compute_args_hash(tool, args, requester, t["expires"])
        cur.execute(
            "INSERT INTO approvals (tool_name, args, args_hash, requester, idempotency_key, expires_at, preview) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING *",
            (tool, Jsonb(args), args_hash, requester, key, t["expires"], Jsonb(jsonable(preview))))
        return cur.fetchone(), False


def status(approval_id: str) -> dict:
    expire_stale()
    row = get_row(approval_id)
    if row is None:
        raise ToolError("NOT_FOUND", f"No approval {approval_id}.", "Check the approval_id.")
    return public_view(row)


# ---- execution --------------------------------------------------------------
_REFUSALS = {
    "PENDING": ("APPROVAL_PENDING", "A human has not approved this yet.", "Wait for approval in the approval UI, then retry."),
    "REJECTED": ("APPROVAL_REJECTED", "A human rejected this request.", "Do not retry. Report the rejection."),
    "EXPIRED": ("APPROVAL_EXPIRED", "The approval expired before it was used.", "Request a new approval. System state may have changed."),
    "EXECUTING": ("EXECUTION_IN_PROGRESS", "Another call is already executing this approval.", "Poll get_approval_status."),
    "FAILED": ("EXECUTION_FAILED", "This approval was used and the execution failed.",
               "Read get_approval_status result for details, then request a new approval if still needed."),
}


def execute(approval_id: str, caller) -> dict:
    expire_stale()
    row = get_row(approval_id)
    if row is None:
        raise ToolError("NOT_FOUND", f"No approval {approval_id}.", "Check the approval_id.")
    if row["requester"] != caller.actor:
        raise ToolError("PERMISSION_DENIED", "Only the identity that requested this action may execute it.", "")
    st = row["status"]
    if st == "EXECUTED":   # idempotent: a repeat call returns the stored result and runs nothing
        return {"status": "ALREADY_EXECUTED", "approval_id": str(row["id"]), "result": row["result"]}
    if st in _REFUSALS:
        raise ToolError(*_REFUSALS[st])

    # st == APPROVED
    if not hash_matches(row):
        audit.write_event(actor=caller.actor, event_type="APPROVAL_HASH_MISMATCH", tool_name=row["tool_name"],
                          approval_id=row["id"], outcome="REFUSED")
        raise ToolError("HASH_MISMATCH", "The stored request does not match its approved hash. Nothing was run.",
                        "Report this to a security owner.")
    fn = EXECUTORS.get(row["tool_name"])
    if fn is None:
        raise ToolError("NO_EXECUTOR", f"No executor registered for {row['tool_name']}.", "")

    # Claim. Only one caller can move APPROVED -> EXECUTING, so a double call cannot run twice.
    with connect("ops_executor") as conn, conn.cursor() as cur:
        cur.execute("UPDATE approvals SET status = 'EXECUTING', started_at = now() WHERE id = %s AND status = 'APPROVED' "
                    "AND expires_at > now() RETURNING id", (row["id"],))
        claimed = cur.fetchone()
    if not claimed:
        raise ToolError("EXECUTION_IN_PROGRESS", "Could not claim this approval: it is already running, finished, or expired.",
                        "Poll get_approval_status.")
    audit.write_event(actor=caller.actor, event_type="APPROVAL_EXECUTION_STARTED", tool_name=row["tool_name"],
                      approval_id=row["id"], outcome="EXECUTING")

    try:
        with connect("ops_executor") as conn, conn.cursor() as cur:
            # Hold the row for the whole execution so the recovery job cannot close it while we run,
            # and confirm the claim is still ours.
            cur.execute("SELECT id FROM approvals WHERE id = %s AND status = 'EXECUTING' FOR UPDATE", (row["id"],))
            if cur.fetchone() is None:
                raise ToolError("EXECUTION_LOST_CLAIM", "This execution was closed by recovery before it could run.",
                                "Nothing was run. Request a new approval if still needed.")
            result = jsonable(fn(row["args"], row, cur))
            cur.execute("UPDATE approvals SET status = 'EXECUTED', executed_at = now(), result = %s "
                        "WHERE id = %s AND status = 'EXECUTING'", (Jsonb(result), row["id"]))
            if cur.rowcount != 1:   # never leave a committed change behind a FAILED approval
                raise ToolError("EXECUTION_LOST_CLAIM", "The approval changed state during execution. Rolled back.",
                                "Nothing was changed. Request a new approval if still needed.")
    except Exception as exc:  # noqa: BLE001
        err = from_exception(exc)["error"]
        with connect("ops_executor") as conn, conn.cursor() as cur:
            cur.execute("UPDATE approvals SET status = 'FAILED', executed_at = now(), result = %s "
                        "WHERE id = %s AND status = 'EXECUTING'", (Jsonb(jsonable({"error": err})), row["id"]))
        audit.write_event(actor=caller.actor, event_type="APPROVAL_EXECUTION_FAILED", tool_name=row["tool_name"],
                          approval_id=row["id"], outcome="FAILED:" + err["code"], output={"error": err})
        # The approval is spent, so retrying execute_approved_action cannot help. The agent must ask again.
        raise ToolError("EXECUTION_FAILED", err["message"],
                        (err.get("hint") or "") + " This approval is used up: request a new one if the action is still needed.",
                        False)

    audit.write_event(actor=caller.actor, event_type="APPROVAL_EXECUTED", tool_name=row["tool_name"],
                      approval_id=row["id"], outcome="EXECUTED", output=_trim(result))
    return {"status": "EXECUTED", "approval_id": str(row["id"]), "result": result}


def _trim(result: dict) -> dict:
    """Keep audit rows small: drop the bulky rollback snapshot (it stays in approvals.result)."""
    return {k: v for k, v in result.items() if k != "rollback_snapshot"}
