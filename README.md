# Governed Ops MCP

Policy-gated MCP server with Postgres, Docker, and human approval for destructive actions.

## Quickstart
```
cp .env.example .env     # set all passwords (letters and digits only)
docker compose up -d --build
docker compose logs migrate
```
`migrate` runs Alembic migrations, then loads seed data once, then exits.
`docker compose down -v` wipes the volume.

## Database roles
| Role | Can do |
|---|---|
| `ops_admin` | Owner. Migrations only. |
| `agent_ro` | SELECT on redacted views (`v_*`). Read-only, 5s timeout. |
| `agent_rw` | UPDATE orders/tickets, INSERT ticket_comments. Used after approval only. |
| `audit_writer` | INSERT and SELECT on `audit_events`. |
