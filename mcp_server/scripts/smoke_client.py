"""End-to-end check through a real MCP client over HTTP.
Run inside the container:  python -m scripts.smoke_client
"""
import asyncio
import json
import os
import re
import sys

import httpx

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from governed.audit import verify_chain
from governed.config import get_settings
from governed.db import connect

URL = os.environ.get("MCP_URL", "http://localhost:8000/mcp")
ACTOR_TOKEN = {actor: tok for tok, (actor, _) in get_settings().api_tokens.items()}
UI = os.environ.get("UI_URL", "http://approval-ui:8000")
APPROVER_PASSWORDS = {"carol": "dev-approver-pass", "alice": "dev-alice-pass"}
RESULTS: list[tuple[str, bool, str]] = []


async def call(token, tool, args=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
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
                return {"ok": False, "error": {"code": "CLIENT_PARSE", "message": text[:200]}}


async def ui_decide(who, approval_id, decision, twice=False):
    """Approve or reject through the real approval UI, the way a human would."""
    async with httpx.AsyncClient(auth=(who, APPROVER_PASSWORDS[who]), follow_redirects=True, timeout=10) as c:
        page = await c.get(f"{UI}/approvals/{approval_id}")
        h = re.search(r'name="args_hash" value="([0-9a-f]{64})"', page.text)
        t = re.search(r'name="csrf" value="([0-9a-f]+)"', page.text)
        if not (h and t):
            return [page.text]
        form = {"decision": decision, "args_hash": h.group(1), "csrf": t.group(1)}
        out = [(await c.post(f"{UI}/approvals/{approval_id}/decide", data=form)).text]
        if twice:   # a double click
            out.append((await c.post(f"{UI}/approvals/{approval_id}/decide", data=form)).text)
        return out


def audit_count(event_type, approval_id):
    with connect("audit_writer") as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM audit_events WHERE event_type = %s AND approval_id = %s", (event_type, approval_id))
        return cur.fetchone()["n"]


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))


def code(res):
    return (res.get("error") or {}).get("code")


async def main():
    op, vw = ACTOR_TOKEN["alice"], ACTOR_TOKEN["bob"]   # alice: operator, bob: viewer

    async with streamablehttp_client(URL, headers={"Authorization": f"Bearer {vw}"}) as (r, w, _):
        async with ClientSession(r, w) as session:
            await session.initialize()
            names = {t.name for t in (await session.list_tools()).tools}
    check("lists 10 tools", names == {"search_logs", "check_service_health", "run_readonly_sql", "get_ticket",
                                      "add_ticket_comment", "draft_postmortem", "execute_sql_mutation",
                                      "restart_service", "execute_approved_action", "get_approval_status"}, str(sorted(names)))

    r = await call(vw, "search_logs", {"service": "payments-service", "level": "ERROR", "since_minutes": 10080, "limit": 5, "reasoning": "smoke"})
    check("search_logs finds the outage", r.get("ok") and r["result"]["returned"] > 0, str(r)[:120])

    r = await call(vw, "search_logs", {"contains": "api_key", "since_minutes": 10080})
    msgs = " ".join(x["message"] for x in r["result"]["rows"]) if r.get("ok") else ""
    check("search_logs redacts secrets", r.get("ok") and "sk_test" not in msgs and "[REDACTED" in msgs, msgs[:120])

    r = await call(vw, "search_logs", {"contains": "SYSTEM NOTE", "since_minutes": 10080})
    check("injection text returned as data only", r.get("ok") and r["result"]["returned"] >= 1)

    r = await call(vw, "get_ticket", {"ticket_id": 31})
    check("get_ticket returns the sev1", r.get("ok") and r["result"]["ticket"]["severity"] == "sev1")

    r = await call(vw, "get_ticket", {"ticket_id": 9999})
    check("get_ticket unknown id -> NOT_FOUND", code(r) == "NOT_FOUND")

    r = await call(vw, "check_service_health", {"service": "payments-service"})
    check("health reports payments status", r.get("ok") and r["result"]["status"] in ("healthy", "degraded"))

    r = await call(vw, "run_readonly_sql", {"sql": "SELECT status, count(*) AS n FROM v_orders GROUP BY status ORDER BY n DESC"})
    check("run_readonly_sql good SELECT", r.get("ok") and r["result"]["row_count"] >= 1)

    r = await call(vw, "run_readonly_sql", {"sql": "SELECT message FROM v_app_logs WHERE message LIKE '%hunter2%' OR message LIKE '%password%'"})
    rows = json.dumps(r["result"]["rows"]) if r.get("ok") else ""
    check("sql results are redacted", r.get("ok") and "hunter2" not in rows and "[REDACTED" in rows, rows[:120])

    for label, sql in {
        "DROP TABLE": "DROP TABLE orders",
        "stacked statements": "SELECT 1; DROP TABLE orders",
        "raw users table": "SELECT * FROM users",
        "pg_sleep": "SELECT pg_sleep(10)",
        "SELECT INTO": "SELECT * INTO x FROM v_orders",
        "FOR UPDATE": "SELECT * FROM v_orders FOR UPDATE",
        "CTE with DELETE": "WITH d AS (DELETE FROM orders RETURNING *) SELECT * FROM d",
        "catalog access": "SELECT * FROM pg_catalog.pg_user",
        "set_config": "SELECT set_config('default_transaction_read_only','off',false)",
    }.items():
        r = await call(vw, "run_readonly_sql", {"sql": sql})
        check(f"sql blocked: {label}", code(r) == "SQL_REJECTED", code(r) or str(r)[:80])

    r = await call(vw, "add_ticket_comment", {"ticket_id": 31, "body": "viewer attempt"})
    check("viewer cannot write (RBAC)", code(r) == "PERMISSION_DENIED")

    r = await call(None, "search_logs", {})
    check("no token -> UNAUTHENTICATED", code(r) == "UNAUTHENTICATED")
    r = await call("wrong-token", "search_logs", {})
    check("bad token -> UNAUTHENTICATED", code(r) == "UNAUTHENTICATED")

    r = await call(op, "add_ticket_comment", {"ticket_id": 31, "body": "Investigating. api_key=sk_test_SMOKE123 was visible in logs.", "reasoning": "smoke"})
    check("operator adds comment", r.get("ok"), str(r)[:100])
    t = await call(op, "get_ticket", {"ticket_id": 31})
    bodies = " ".join(c["body"] for c in t["result"]["comments"]) if t.get("ok") else ""
    check("comment secret was redacted before saving", "SMOKE123" not in bodies and "[REDACTED" in bodies)

    r = await call(op, "draft_postmortem", {"ticket_id": 31, "reasoning": "smoke"})
    check("draft_postmortem saves a draft", r.get("ok") and "DRAFT POSTMORTEM" in r["result"]["draft"], str(r)[:100])


    # ---------------- Tier 3: request, approve, execute ----------------
    dana = ACTOR_TOKEN["dana"]
    r = await call(vw, "restart_service", {"service": "payments-service"})
    check("viewer cannot request a restart (RBAC)", code(r) == "PERMISSION_DENIED")

    for label, sql in {
        "DROP TABLE": "DROP TABLE orders",
        "DELETE": "DELETE FROM orders WHERE id = 1",
        "UPDATE users": "UPDATE users SET plan = 'free' WHERE id = 1",
        "UPDATE protected column": "UPDATE orders SET total_cents = 0 WHERE id = 1",
        "UPDATE without WHERE": "UPDATE orders SET status = 'failed'",
        "stacked statements": "UPDATE orders SET status = 'failed' WHERE id = 1; DROP TABLE orders",
        "pg_sleep in SET": "UPDATE orders SET status = pg_sleep(5)::text WHERE id = 1",
    }.items():
        r = await call(op, "execute_sql_mutation", {"sql": sql})
        check(f"mutation rejected: {label}", code(r) == "SQL_REJECTED", code(r) or str(r)[:80])

    r = await call(op, "execute_sql_mutation", {"sql": "UPDATE orders SET status = 'failed' WHERE id = -1"})
    check("mutation matching zero rows -> NO_ROWS_MATCHED", code(r) == "NO_ROWS_MATCHED")

    sql = "UPDATE tickets SET status = 'investigating' WHERE id = 31"
    r = await call(op, "execute_sql_mutation", {"sql": sql, "reasoning": "smoke: mark the sev1 as investigating"})
    res = r.get("result", {})
    aid = res.get("approval_id")
    check("mutation request returns PENDING_APPROVAL", r.get("ok") and res.get("status") == "PENDING_APPROVAL" and aid, str(r)[:120])
    check("request shows blast radius and a SHA-256", res.get("preview", {}).get("rows_matched") == 1
          and re.fullmatch(r"[0-9a-f]{64}", res.get("args_hash", "")), str(res)[:120])

    r = await call(op, "execute_sql_mutation", {"sql": sql})
    check("repeating the request returns the same approval (idempotent)", r.get("result", {}).get("approval_id") == aid)

    r = await call(op, "execute_approved_action", {"approval_id": aid})
    check("execute before approval -> APPROVAL_PENDING", code(r) == "APPROVAL_PENDING")
    r = await call(vw, "get_approval_status", {"approval_id": aid})
    check("status is PENDING", r.get("ok") and r["result"]["status"] == "PENDING")

    pages = await ui_decide("alice", aid, "approve")
    check("requester cannot approve their own request", "cannot approve your own" in pages[0], pages[0][-200:] if "cannot approve" not in pages[0] else "")

    pages = await ui_decide("carol", aid, "approve", twice=True)
    check("human approves in the UI", "Approved. The agent can now execute it" in pages[0])
    check("double click does not decide twice", "already decided" in pages[1])

    r = await call(dana, "execute_approved_action", {"approval_id": aid})
    check("a different operator cannot execute it", code(r) == "PERMISSION_DENIED")
    r = await call(vw, "execute_approved_action", {"approval_id": aid})
    check("viewer cannot execute (RBAC)", code(r) == "PERMISSION_DENIED")

    r = await call(op, "execute_approved_action", {"approval_id": aid, "reasoning": "smoke"})
    res = r.get("result", {})
    check("approved mutation executes once", r.get("ok") and res.get("status") == "EXECUTED"
          and res["result"]["rows_affected"] == 1, str(r)[:160])
    check("execution returns a rollback hint and snapshot", "UPDATE tickets SET" in res.get("result", {}).get("rollback_hint", "")
          and len(res["result"]["rollback_snapshot"]["rows"]) == 1)

    r2 = await call(op, "execute_approved_action", {"approval_id": aid})
    check("second execute returns ALREADY_EXECUTED", r2.get("ok") and r2["result"]["status"] == "ALREADY_EXECUTED"
          and r2["result"]["result"] == res["result"])
    check("the change ran exactly once (audit)", audit_count("APPROVAL_EXECUTED", aid) == 1, str(audit_count("APPROVAL_EXECUTED", aid)))

    r = await call(vw, "run_readonly_sql", {"sql": "SELECT status FROM v_tickets WHERE id = 31"})
    check("ticket really changed", r.get("ok") and r["result"]["rows"][0]["status"] == "investigating")

    r = await call(op, "restart_service", {"service": "auth-service", "reasoning": "smoke: exercise the restart flow"})
    rid = r.get("result", {}).get("approval_id")
    check("restart request is pending", r.get("ok") and r["result"]["status"] == "PENDING_APPROVAL" and rid)
    await ui_decide("carol", rid, "approve")
    r = await call(op, "execute_approved_action", {"approval_id": rid})
    check("approved restart executes", r.get("ok") and r["result"]["status"] == "EXECUTED"
          and r["result"]["result"]["status"] == "healthy", str(r)[:140])
    r = await call(vw, "check_service_health", {"service": "auth-service"})
    check("auth-service is healthy after the restart", r.get("ok") and r["result"]["status"] == "healthy")

    r = await call(op, "restart_service", {"service": "api-gateway"})
    xid = r.get("result", {}).get("approval_id")
    pages = await ui_decide("carol", xid, "reject")
    check("human rejects in the UI", "Rejected" in pages[0])
    r = await call(op, "execute_approved_action", {"approval_id": xid})
    check("rejected request cannot execute", code(r) == "APPROVAL_REJECTED")

    r = await call(op, "restart_service", {"service": "not-a-service"})
    check("restart of unknown service rejected", code(r) == "INVALID_ARGUMENT")

    v = verify_chain()
    check("audit chain verifies", v["ok"] and v["checked"] > 50, str(v))

    width = max(len(n) for n, _, _ in RESULTS)
    for name, ok, detail in RESULTS:
        print(f"{'PASS' if ok else 'FAIL'}  {name.ljust(width)}" + ("" if ok or not detail else f"   {detail}"))
    passed = sum(ok for _, ok, _ in RESULTS)
    print(f"\n{passed}/{len(RESULTS)} passed")
    sys.exit(0 if passed == len(RESULTS) else 1)


asyncio.run(main())
