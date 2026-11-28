"""Plumbing for the eval scenarios: an MCP client, the approval UI as a human uses it, and read access to the
audit log. Scenarios play the part of an agent that is compromised or manipulated and check that the
governance layer holds. No LLM is involved: every scenario is a fixed script with a fixed expected result."""
import json
import os
import re
import uuid
from dataclasses import dataclass, field

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from governed.config import get_settings
from governed.db import connect

URL = os.environ.get("MCP_URL", "http://localhost:8000/mcp")
UI = os.environ.get("UI_URL", "http://approval-ui:8000")
APPROVER_PASSWORDS = {"carol": "dev-approver-pass", "alice": "dev-alice-pass"}
TOKENS = {actor: tok for tok, (actor, _) in get_settings().api_tokens.items()}
HARMLESS_SQL = "UPDATE tickets SET status = 'investigating' WHERE id = 31"   # a change that is safe to really run


def uid() -> str:
    return uuid.uuid4().hex[:12]


async def call(who: str | None, tool: str, args: dict | None = None, token: str | None = None) -> dict:
    """Call a tool as a named actor (alice, bob, dana), as nobody (None), or with a raw token."""
    tok = token if token is not None else (TOKENS[who] if who else None)
    headers = {"Authorization": f"Bearer {tok}"} if tok else {}
    async with streamablehttp_client(URL, headers=headers) as (r, w, _):
        async with ClientSession(r, w) as session:
            await session.initialize()
            res = await session.call_tool(tool, args or {})
            if getattr(res, "structuredContent", None):
                return res.structuredContent
            text = "".join(c.text for c in res.content if getattr(c, "text", None))
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"ok": False, "error": {"code": "CLIENT_REJECTED", "message": text[:200]}}


def code(r: dict) -> str | None:
    return (r.get("error") or {}).get("code")


def rows(r: dict) -> list[dict]:
    return (r.get("result") or {}).get("rows", [])


async def sql(who: str, query: str) -> dict:
    return await call(who, "run_readonly_sql", {"sql": query})


async def request_fix(who: str = "alice", statement: str = HARMLESS_SQL) -> tuple[str | None, str | None, dict]:
    """Ask for a Tier 3 change with a fresh idempotency key. Returns (approval_id, args_hash, raw response)."""
    r = await call(who, "execute_sql_mutation", {"sql": statement, "idempotency_key": f"eval-{uid()}", "reasoning": "eval"})
    res = r.get("result") or {}
    return res.get("approval_id"), res.get("args_hash"), r


async def approval_status(approval_id: str) -> str | None:
    r = await call("bob", "get_approval_status", {"approval_id": approval_id})
    return (r.get("result") or {}).get("status")


# ---- the approval UI, driven the way a browser does it ------------------------------------------------------

async def ui_page(who: str, approval_id: str) -> tuple[str | None, str | None, str]:
    async with httpx.AsyncClient(auth=(who, APPROVER_PASSWORDS[who]), follow_redirects=True, timeout=10) as c:
        text = (await c.get(f"{UI}/approvals/{approval_id}")).text
    h = re.search(r'name="args_hash" value="([0-9a-f]{64})"', text)
    t = re.search(r'name="csrf" value="([0-9a-f]+)"', text)
    return (h.group(1) if h else None), (t.group(1) if t else None), text


async def ui_decide(who: str, approval_id: str, decision: str = "approve") -> str:
    h, t, page = await ui_page(who, approval_id)
    if not (h and t):
        return page
    async with httpx.AsyncClient(auth=(who, APPROVER_PASSWORDS[who]), follow_redirects=True, timeout=10) as c:
        return (await c.post(f"{UI}/approvals/{approval_id}/decide",
                             data={"decision": decision, "args_hash": h, "csrf": t})).text


# ---- the audit log (read-only) ------------------------------------------------------------------------------

def last_audit_id() -> int:
    with connect("audit_writer") as conn, conn.cursor() as cur:
        cur.execute("SELECT coalesce(max(id), 0) AS m FROM audit_events")
        return cur.fetchone()["m"]


def audit_count(after_id: int, **where) -> int:
    clauses, params = ["id > %s"], [after_id]
    for col, val in where.items():
        clauses.append(f"{col} = %s")
        params.append(val)
    with connect("audit_writer") as conn, conn.cursor() as cur:
        cur.execute(f"SELECT count(*) AS n FROM audit_events WHERE {' AND '.join(clauses)}", params)
        return cur.fetchone()["n"]


def audit_text_since(after_id: int) -> str:
    """Everything the audit log stored since `after_id`, as one string, for searching."""
    with connect("audit_writer") as conn, conn.cursor() as cur:
        cur.execute("SELECT coalesce(args::text, '') || coalesce(output::text, '') || coalesce(agent_reasoning, '') AS t "
                    "FROM audit_events WHERE id > %s", (after_id,))
        return " ".join(r["t"] for r in cur.fetchall())


@dataclass
class Checks:
    """The individual assertions inside one scenario. The scenario is defended only if all of them hold."""
    items: list[tuple[str, bool, str]] = field(default_factory=list)

    def expect(self, label: str, condition, detail: str = "") -> None:
        self.items.append((label, bool(condition), detail))

    @property
    def ok(self) -> bool:
        return bool(self.items) and all(ok for _, ok, _ in self.items)

    def evidence(self) -> str:
        failed = [f"{label}{' (' + d + ')' if d else ''}" for label, ok, d in self.items if not ok]
        return "FAILED: " + "; ".join(failed) if failed else f"{len(self.items)} checks held"
