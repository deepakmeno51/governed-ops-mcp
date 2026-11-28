"""Plays the incident from the demo: an agent triages the outage, asks to fix it, and waits for a human.
Run:  python -m scripts.demo_outage      Then open http://localhost:8003 and approve the request.
CI:   python -m scripts.demo_outage --auto-approve   approves through the same approval UI, as the dev approver.
Works once per fresh database (the fix changes the stuck orders). Reset with: docker compose down -v
"""
import asyncio
import json
import os
import re
import sys
import time

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from governed.config import get_settings

URL = os.environ.get("MCP_URL", "http://localhost:8000/mcp")
TOKEN = next(t for t, (_, role) in get_settings().api_tokens.items() if role == "operator")
UI_URL = os.environ.get("UI_URL", "http://localhost:8003")
AUTO_APPROVE = "--auto-approve" in sys.argv
APPROVER = ("carol", "dev-approver-pass")
FIX_SQL = "UPDATE orders SET status = 'pending' WHERE status = 'processing' AND updated_at < now() - interval '15 minutes'"


async def call(tool, args=None):
    async with streamablehttp_client(URL, headers={"Authorization": f"Bearer {TOKEN}"}) as (r, w, _):
        async with ClientSession(r, w) as session:
            await session.initialize()
            res = await session.call_tool(tool, args or {})
            return res.structuredContent or json.loads("".join(c.text for c in res.content))


def approve_through_ui(approval_id: str, expected_hash: str) -> None:
    """What a human does in the browser, done over HTTP: open the request, check the hash, click Approve."""
    with httpx.Client(auth=APPROVER, follow_redirects=True, timeout=10) as c:
        page = c.get(f"{UI_URL}/approvals/{approval_id}").text
        shown = re.search(r'name="args_hash" value="([0-9a-f]{64})"', page)
        csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', page)
        if not (shown and csrf):
            sys.exit("    auto-approve: could not read the approval page")
        if shown.group(1) != expected_hash:
            sys.exit("    auto-approve: the hash on the page differs from the request hash. Not approving.")
        print(f"    [auto-approve] {APPROVER[0]} checked the hash on the page matches, clicking Approve")
        c.post(f"{UI_URL}/approvals/{approval_id}/decide",
               data={"decision": "approve", "args_hash": shown.group(1), "csrf": csrf.group(1)})


def say(step, text):
    print(f"\n[{step}] {text}", flush=True)


async def main():
    say("1 triage", "Checking service health")
    h = await call("check_service_health", {"reasoning": "alert fired, find the degraded service"})
    print("   ", h["result"]["services"])

    say("2 triage", "Searching payments-service errors (last 7 days)")
    r = await call("search_logs", {"service": "payments-service", "level": "ERROR", "since_minutes": 10080, "limit": 3})
    print("   ", r["result"]["matched_by_level"], "| e.g.", r["result"]["rows"][0]["message"])

    say("3 triage", "Counting stuck orders")
    r = await call("run_readonly_sql", {"sql": "SELECT count(*) AS stuck FROM v_orders WHERE status = 'processing'"})
    print("   ", r["result"]["rows"])

    say("4 fix", "Requesting the fix. This does NOT run it.")
    r = await call("execute_sql_mutation", {"sql": FIX_SQL, "idempotency_key": "demo-fix-orders-1",
                                            "reasoning": "orders stuck in processing since the payments pool exhausted; reset to pending so they retry"})
    if not r.get("ok"):
        if r["error"]["code"] == "NO_ROWS_MATCHED":
            print("    No stuck orders match. This database was already fixed. Reset with: docker compose down -v")
            sys.exit(0)
        print("   ", r["error"]); sys.exit(1)
    req = r["result"]
    print(f"    approval_id : {req['approval_id']}")
    print(f"    will change : {req['preview']['rows_matched']} rows in {req['preview']['table']}")
    print(f"    request hash: {req['args_hash']}")
    print(f"    expires     : {req['expires_at']}")
    if AUTO_APPROVE:
        approve_through_ui(req["approval_id"], req["args_hash"])
    else:
        print(f"\n    >>> Open http://localhost:8003 (carol / dev-approver-pass), review the SQL and click Approve <<<")

    say("5 wait", "Polling for the human decision (up to 10 minutes, backing off from 2s to 10s)")
    deadline = time.time() + 600
    status, delay = "PENDING", 2.0
    while time.time() < deadline:
        st = await call("get_approval_status", {"approval_id": req["approval_id"]})
        status = st["result"]["status"]
        if status != "PENDING":
            break
        await asyncio.sleep(delay)
        delay = min(delay * 1.5, 10.0)      # every poll is audited, so do not poll tightly
    print(f"    status: {status}")
    if status != "APPROVED":
        print("    Not approved, so the agent stops here."); sys.exit(0)

    say("6 execute", "Executing the approved request")
    r = await call("execute_approved_action", {"approval_id": req["approval_id"], "reasoning": "approved by a human"})
    if not r.get("ok"):
        print("   ", r["error"]); sys.exit(1)
    out = r["result"]["result"]
    print(f"    rows changed: {out['rows_affected']}")
    print(f"    undo hint   : {out['rollback_hint'][:140]}...")

    say("7 verify", "Counting stuck orders again")
    r = await call("run_readonly_sql", {"sql": "SELECT count(*) AS stuck FROM v_orders WHERE status = 'processing'"})
    print("   ", r["result"]["rows"])
    print("\nDone. Check the audit trail:  python -m scripts.verify_audit")


if __name__ == "__main__":
    asyncio.run(main())
