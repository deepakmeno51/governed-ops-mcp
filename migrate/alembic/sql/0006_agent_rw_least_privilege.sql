-- Day 11: make the database enforce the same allowlist as the SQL guard (MUTABLE_COLUMNS in sqlguard.py).
-- Before: agent_rw could UPDATE every column of orders and tickets, so only the guard stood between an
-- approved-looking statement and, say, UPDATE orders SET total_cents = 0.
-- After: orders(status) and tickets(status, severity) only. SELECT and INSERT ticket_comments are unchanged.
REVOKE UPDATE ON orders, tickets FROM agent_rw;
GRANT UPDATE (status) ON orders TO agent_rw;
GRANT UPDATE (status, severity) ON tickets TO agent_rw;
