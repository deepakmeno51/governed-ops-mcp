"""Tier 3 tools. These never run on request. They create an approval for a human.
After approval, execute_approved_action runs the stored request exactly once."""
from datetime import datetime, timezone

import httpx

from governed import approvals
from governed.config import get_settings
from governed.db import connect
from governed.decorator import CURRENT_IDENTITY, governed_tool
from governed.errors import ToolError
from governed.policy import Prepared, Tier
from governed.sqlguard import plan_update
from tools.telemetry import KNOWN_SERVICES


# ---- execute_sql_mutation ---------------------------------------------------
def prepare_sql_mutation(sql: str) -> Prepared:
    plan = plan_update(sql)
    cap = get_settings().max_mutation_rows
    with connect("agent_rw") as conn:
        conn.read_only = True          # the preview can read but never write
        with conn.cursor() as cur:
            cur.execute(plan.count_sql)
            matched = cur.fetchone()["n"]
            cur.execute(plan.sample_sql)
            sample = [r["id"] for r in cur.fetchall()]
    if matched == 0:
        raise ToolError("NO_ROWS_MATCHED", "The WHERE clause matches no rows, so there is nothing to change.",
                        "Check the condition with run_readonly_sql first.")
    if matched > cap:
        raise ToolError("BLAST_RADIUS_TOO_LARGE", f"The WHERE clause matches {matched} rows. The limit is {cap}.",
                        "Narrow the condition and request again.")
    return Prepared(
        args={"sql": plan.sql},
        summary=f"UPDATE {plan.table} ({', '.join(plan.columns)}) on {matched} row(s)",
        preview={"kind": "sql_update", "table": plan.table, "columns": plan.columns, "rows_matched": matched,
                 "sample_ids": sample, "snapshot_at": datetime.now(timezone.utc).isoformat(timespec="seconds")},
    )


def _quote(v) -> str:
    return "NULL" if v is None else "'" + str(v).replace("'", "''") + "'"


def exec_sql_mutation(args: dict, row: dict, cur) -> dict:
    """Runs inside one transaction. Acts as agent_rw (SELECT, UPDATE on two tables) for the statement only."""
    plan = plan_update(args["sql"])                      # validate again at execution time
    approved_rows = (row["preview"] or {}).get("rows_matched", 0)
    cur.execute("SET LOCAL ROLE agent_rw")
    cur.execute("SET LOCAL statement_timeout = '15s'")
    cur.execute("SET LOCAL lock_timeout = '3s'")
    cur.execute(plan.count_sql)
    now_matched = cur.fetchone()["n"]
    if now_matched > approved_rows:
        raise ToolError("STATE_CHANGED", f"{now_matched} rows match now, but {approved_rows} were approved. Nothing was changed.",
                        "Request a new approval.")
    cur.execute(plan.snapshot_sql)
    snapshot = cur.fetchall()
    cur.execute(plan.sql)
    affected = cur.rowcount
    cur.execute("RESET ROLE")

    groups: dict = {}
    for r in snapshot:
        groups.setdefault(tuple(r[c] for c in plan.columns), []).append(r["id"])
    undo = []
    for old, ids in list(groups.items())[:5]:
        sets = ", ".join(f"{c} = {_quote(v)}" for c, v in zip(plan.columns, old))
        undo.append(f"UPDATE {plan.table} SET {sets} WHERE id IN ({', '.join(map(str, ids[:500]))})")
    return {
        "rows_affected": affected,
        "table": plan.table,
        "columns": plan.columns,
        "rollback_snapshot": {"columns": ["id"] + plan.columns, "rows": snapshot},
        "rollback_hint": "To undo, run these as a new approved request (or by a DBA): " + "; ".join(undo),
    }


@governed_tool(Tier.DESTRUCTIVE, prepare=prepare_sql_mutation, execute=exec_sql_mutation)
def execute_sql_mutation(sql: str, idempotency_key: str = "", reasoning: str = "") -> dict:
    """Request a database change (Tier 3, destructive). This does NOT run the change.
    It creates an approval request that a human must approve in the approval UI.
    Allowed: one UPDATE ... WHERE on orders(status) or tickets(status, severity), up to 1000 rows.
    Returns approval_id, the SHA-256 of the exact request, and how many rows it would change.
    After a human approves, call execute_approved_action(approval_id). Requests expire in 10 minutes.
    Pass `idempotency_key` so a retry returns the same request. Pass `reasoning` with a one-line reason."""
    raise RuntimeError("handled by governed_tool")


# ---- restart_service --------------------------------------------------------
def prepare_restart(service: str) -> Prepared:
    if service not in KNOWN_SERVICES:
        raise ToolError("INVALID_ARGUMENT", f"Unknown service '{service}'.", f"Use one of: {', '.join(KNOWN_SERVICES)}.")
    try:
        with httpx.Client(timeout=3.0) as c:
            current = c.get(f"{get_settings().mock_service_url}/health/{service}").json().get("status", "unknown")
    except httpx.HTTPError:
        current = "unknown"
    return Prepared(
        args={"service": service},
        summary=f"Restart {service} (currently {current})",
        preview={"kind": "restart", "service": service, "current_status": current,
                 "note": "In-flight requests on this service are dropped during the restart."},
    )


def exec_restart(args: dict, row: dict, cur) -> dict:
    try:
        with httpx.Client(timeout=5.0) as c:
            resp = c.post(f"{get_settings().mock_service_url}/restart/{args['service']}")
            resp.raise_for_status()
            return resp.json()
    except httpx.TimeoutException:
        raise ToolError("DOWNSTREAM_TIMEOUT", "The restart call timed out. The service may or may not have restarted.",
                        "Check check_service_health before requesting another restart.", False)


@governed_tool(Tier.DESTRUCTIVE, prepare=prepare_restart, execute=exec_restart)
def restart_service(service: str, idempotency_key: str = "", reasoning: str = "") -> dict:
    """Request a service restart (Tier 3, destructive). This does NOT restart anything.
    It creates an approval request that a human must approve in the approval UI.
    Services: api-gateway, orders-service, payments-service, auth-service.
    After a human approves, call execute_approved_action(approval_id). Requests expire in 10 minutes.
    Pass `reasoning` with a one-line reason."""
    raise RuntimeError("handled by governed_tool")


# ---- execute_approved_action / get_approval_status --------------------------
@governed_tool(Tier.DESTRUCTIVE, self_gated=True)
def execute_approved_action(approval_id: str, reasoning: str = "") -> dict:
    """Run a request that a human approved (Tier 3, operators only, only the original requester).
    Runs once. Calling it again returns the stored result without running anything.
    Refuses if the request is pending, rejected, expired, changed, or already running."""
    return approvals.execute(approval_id, CURRENT_IDENTITY.get())


@governed_tool(Tier.READ)
def get_approval_status(approval_id: str, reasoning: str = "") -> dict:
    """Check an approval request (Tier 1, read-only).
    Status: PENDING, APPROVED, REJECTED, EXPIRED, EXECUTING, EXECUTED, FAILED."""
    return approvals.status(approval_id)
