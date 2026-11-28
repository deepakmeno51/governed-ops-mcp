# Demo recording script

Target length: 3 to 4 minutes. Story: **an AI agent can triage an outage, but it cannot change production until a human approves the exact command.**

I cannot record this for you. On Windows, press `Win+G` (Xbox Game Bar) and start recording, or use OBS. Use a terminal font of 18 pt or more, and keep the browser and terminal side by side.

## Before you hit record
```
docker compose down -v
docker compose up -d --build
docker compose ps                      # everything healthy
```
Open `http://localhost:8003` in the browser and log in as `carol` / `dev-approver-pass`. Leave the queue page open.
A fresh database matters: the demo needs the 250 stuck orders. `make demo-reset` does the same.

## Storyboard

| Time | On screen | Say |
|---|---|---|
| 0:00 | README top, architecture diagram | "Agents are useful for incident response but risky around production data. This server puts a policy layer between the agent and Postgres." |
| 0:20 | Terminal: `docker compose exec mcp-server python -m scripts.demo_outage` | "Payments are degraded and orders are stuck. The agent triages using read-only tools." |
| 0:40 | Steps 1 to 3 print | "It sees health, 1,842 errors and 250 stuck orders. Reads are Tier 1: allowed, audited, redacted." |
| 1:00 | Step 4 prints, request hash | "It asks for a fix. That is a Tier 3 tool, so nothing runs. It created a request, bound to a SHA-256 of the exact command." |
| 1:15 | Browser: refresh queue, open the request | "A human reviews the exact SQL, 250 rows in `orders`, the hash and the expiry." |
| 1:40 | Click Approve | "Approval is made with a different role. The agent's database role cannot approve, enforced by a trigger, not by app code." |
| 1:55 | Terminal moves on: executed, 250 rows changed, stuck 0 | "The agent executes by approval id only. It cannot swap the SQL. The server rechecks the hash and runs it once." |
| 2:15 | `docker compose exec mcp-server python -m scripts.verify_audit` | "Every step is in an append-only, hash-chained audit log. This verifies the chain." |
| 2:35 | `docker compose exec mcp-server python -m evals.run` | "24 adversarial scenarios: prompt injection, SQL tricks, forged approvals, replay, secret leaks. All defended." |
| 3:15 | `SECURITY.md` limitations section | "And here is what it does not do: no TLS, static tokens, demo credentials." |

## Optional extras (30 s each)
- Click Approve twice quickly: the second click changes nothing.
- Run the demo again without resetting: the agent finds 0 stuck orders and says so.
- Try self-approval: log in as `alice` (the operator behind the demo token) and approve her own request. It is refused.

## If something goes wrong on camera
- Demo shows "no rows matched": the database was already fixed. `make demo-reset`.
- Step 5 waits forever: you did not approve within 10 minutes and it expired. Run the demo again.
- No time for a human click: `make demo-auto` approves through the real UI automatically, and checks that the page shows the same hash as the request.
