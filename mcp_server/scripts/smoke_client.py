"""End-to-end check through a real MCP client over HTTP.
Run inside the container:  python -m scripts.smoke_client
"""
import asyncio
import json
import os
import sys

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from governed.audit import verify_chain
from governed.config import get_settings

URL = os.environ.get("MCP_URL", "http://localhost:8000/mcp")
TOKENS = {role: tok for tok, (_, role) in get_settings().api_tokens.items()}
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


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))


def code(res):
    return (res.get("error") or {}).get("code")


async def main():
    op, vw = TOKENS["operator"], TOKENS["viewer"]

    async with streamablehttp_client(URL, headers={"Authorization": f"Bearer {vw}"}) as (r, w, _):
        async with ClientSession(r, w) as session:
            await session.initialize()
            names = {t.name for t in (await session.list_tools()).tools}
    check("lists 6 tools", names == {"search_logs", "check_service_health", "run_readonly_sql",
                                     "get_ticket", "add_ticket_comment", "draft_postmortem"}, str(sorted(names)))

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
    check("health shows payments degraded", r.get("ok") and r["result"]["status"] == "degraded")

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

    v = verify_chain()
    check("audit chain verifies", v["ok"] and v["checked"] > 20, str(v))

    width = max(len(n) for n, _, _ in RESULTS)
    for name, ok, detail in RESULTS:
        print(f"{'PASS' if ok else 'FAIL'}  {name.ljust(width)}" + ("" if ok or not detail else f"   {detail}"))
    passed = sum(ok for _, ok, _ in RESULTS)
    print(f"\n{passed}/{len(RESULTS)} passed")
    sys.exit(0 if passed == len(RESULTS) else 1)


asyncio.run(main())
