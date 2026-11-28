"""Shared helpers: call a governed tool in-process with a fake request, read the audit log, make approvals."""
import asyncio
import uuid
from types import SimpleNamespace

from governed import approvals
from governed.config import get_settings
from governed.db import connect

REQ = "pytest-requester"


def token_for(actor: str) -> str:
    return next(t for t, (a, _) in get_settings().api_tokens.items() if a == actor)


def call(tool, actor: str | None = None, token: str | None = None, **kwargs) -> dict:
    """Call a decorated tool the way the MCP server does: with an Authorization header on the request."""
    token = token or (token_for(actor) if actor else None)
    headers = {"authorization": f"Bearer {token}"} if token else {}
    ctx = SimpleNamespace(request_context=SimpleNamespace(request=SimpleNamespace(headers=headers)))
    return asyncio.run(tool(ctx=ctx, **kwargs))


def code(response: dict) -> str | None:
    return (response.get("error") or {}).get("code")


def last_audit_id() -> int:
    with connect("audit_writer") as conn, conn.cursor() as cur:
        cur.execute("SELECT coalesce(max(id), 0) AS m FROM audit_events")
        return cur.fetchone()["m"]


def audit_rows(tool_name: str | None = None, *, after_id: int = 0, event_type: str | None = None, approval_id=None) -> list[dict]:
    with connect("audit_writer") as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM audit_events WHERE id > %s AND (%s::text IS NULL OR tool_name = %s) "
                    "AND (%s::text IS NULL OR event_type = %s) AND (%s::uuid IS NULL OR approval_id = %s) ORDER BY id",
                    (after_id, tool_name, tool_name, event_type, event_type, approval_id, approval_id))
        return cur.fetchall()


def new_request(tool="t_test", ttl=1.0, requester=REQ, args=None, **extra):
    row, _ = approvals.create_request(tool=tool, args=args or {"n": uuid.uuid4().hex}, requester=requester,
                                      preview={"summary": "pytest request"}, ttl_minutes=ttl, **extra)
    return row


def decide(row, who="approver-1", status="APPROVED") -> int:
    """Approve or reject as the approval_decider role, the way the approval UI does."""
    with connect("approval_decider") as conn, conn.cursor() as cur:
        cur.execute("UPDATE approvals SET status = %s, decided_by = %s, decided_at = now() "
                    "WHERE id = %s AND status = 'PENDING'", (status, who, row["id"]))
        return cur.rowcount


def claim(row, started_seconds_ago: float = 0.0) -> None:
    """Move an APPROVED request to EXECUTING as ops_executor, with started_at in the past if asked."""
    with connect("ops_executor") as conn, conn.cursor() as cur:
        cur.execute("UPDATE approvals SET status = 'EXECUTING', started_at = now() - make_interval(secs => %s) "
                    "WHERE id = %s AND status = 'APPROVED'", (started_seconds_ago, row["id"]))
        assert cur.rowcount == 1


def status_of(row) -> dict:
    return approvals.get_row(str(row["id"]))
