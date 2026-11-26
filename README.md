# Governed Ops MCP

Policy-gated MCP server with Postgres, Docker, and human approval for destructive actions.

## Quickstart
```
cp .env.example .env     # set all passwords (letters and digits only)
docker compose up -d --build
docker compose exec mcp-server python -m scripts.smoke_client   # 25 end-to-end checks
docker compose exec mcp-server python -m pytest -q              # unit tests
docker compose exec mcp-server python -m scripts.verify_audit   # audit chain check
```
MCP endpoint: `http://localhost:8002/mcp` (header `Authorization: Bearer dev-operator-token`).
Dev tokens live in `docker-compose.yml`. Override with `MCP_API_TOKENS` in `.env`.

## Tools
| Tool | Tier | Roles | Behavior |
|---|---|---|---|
| `search_logs`, `check_service_health`, `get_ticket`, `run_readonly_sql` | 1 | viewer, operator | Run immediately |
| `add_ticket_comment`, `draft_postmortem` | 2 | operator | Run, audited |
| `execute_sql_mutation`, `restart_service` | 3 | operator (request only) | Blocked until human approval (Day 6-9) |

## Request path
identity (bearer token) → role check → tier gate → audit `TOOL_CALL` → run → redact output → audit `TOOL_RESULT`.
No audit record means no action. Errors return a code, message, and hint, never a stack trace.

## Database roles
| Role | Can do |
|---|---|
| `ops_admin` | Owner. Migrations only. |
| `agent_ro` | SELECT on redacted views (`v_*`). Read-only, 5s timeout. |
| `agent_rw` | UPDATE orders/tickets, INSERT ticket_comments. |
| `audit_writer` | INSERT and SELECT on `audit_events`. |

## Layers that stop a bad query
1. `sqlglot` guard: one SELECT, allowed views only, no unknown functions. The server runs the regenerated SQL, not the raw string.
2. `agent_ro` has SELECT on views only, so raw tables and DDL fail.
3. Read-only transaction and a 5 second timeout.

## Audit log
Append-only table, triggers block UPDATE, DELETE and TRUNCATE, and each row stores `sha256(prev_hash + row)`.
`verify_audit` recomputes the chain and reports the first edited row.


## Progress

### Days 3-5: MCP server, governance layer, audit log
- **MCP server** (FastMCP, Docker, bearer-token auth) with four read tools and two audited write tools.
- **`@governed_tool` decorator.** Each call passes identity, role check, risk-tier gate, audit, redaction, audit. If the audit write fails, the action does not run.
- **SELECT-only SQL guard.** `sqlglot` parses the query, allows one SELECT over redacted views, and rejects `DROP`, stacked statements, `SELECT INTO`, `pg_sleep`, and catalog reads. The server runs the regenerated SQL, not the raw string.
- **Defense in depth.** Even if the guard failed, the `agent_ro` database role has SELECT on views only, runs read-only, and times out at 5 seconds.
- **Secret redaction** in database views, tool output, and saved comments.
- **Hash-chained audit log.** Append-only table, triggers block UPDATE, DELETE and TRUNCATE, and each row stores `sha256(prev_hash + row)`. Editing a row with the triggers disabled is caught and the first bad row is reported.
- **Structured errors** with a code, message, and retry hint. No stack traces reach the agent.
- **Tests:** 25 end-to-end checks through a real MCP client and 36 unit tests, including concurrent audit writers.

Tier 3 tools (`execute_sql_mutation`, `restart_service`) fail closed until the approval flow ships (Days 6-9).
