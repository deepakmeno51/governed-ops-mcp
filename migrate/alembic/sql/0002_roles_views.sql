-- Redaction function: secrets, bearer tokens, API keys, emails
CREATE FUNCTION redact_text(t text) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $f$
  SELECT regexp_replace(
         regexp_replace(
         regexp_replace(
         regexp_replace(t,
           '(password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*\S+', '\1=[REDACTED]', 'gi'),
           '\m(sk|pk|rk)_(live|test)_\w+', '[REDACTED_KEY]', 'g'),
           'Bearer\s+[A-Za-z0-9._\-]+', 'Bearer [REDACTED]', 'gi'),
           '[A-Za-z0-9._+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', '[REDACTED_EMAIL]', 'g')
$f$;

-- Views the agent reads. Allowlisted columns, redacted text.
CREATE VIEW v_users AS
  SELECT id, plan, created_at,
         left(email, 1) || '***' || substr(email, strpos(email, '@')) AS email_masked
  FROM users;

CREATE VIEW v_orders AS
  SELECT id, user_id, status, total_cents, currency, created_at, updated_at
  FROM orders;

CREATE VIEW v_app_logs AS
  SELECT id, ts, service, level, redact_text(message) AS message, trace_id
  FROM app_logs;

CREATE VIEW v_tickets AS
  SELECT id, title, redact_text(description) AS description, status, severity, service, created_at, updated_at
  FROM tickets;

CREATE VIEW v_ticket_comments AS
  SELECT id, ticket_id, author, redact_text(body) AS body, created_at
  FROM ticket_comments;

-- Lock everything down, then grant the minimum
REVOKE ALL ON ALL TABLES    IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO agent_ro, agent_rw, audit_writer;

-- agent_ro: views only
GRANT SELECT ON v_users, v_orders, v_app_logs, v_tickets, v_ticket_comments TO agent_ro;
GRANT EXECUTE ON FUNCTION redact_text(text) TO agent_ro;   -- views call it as the invoking role
ALTER ROLE agent_ro SET default_transaction_read_only = on;
ALTER ROLE agent_ro SET statement_timeout = '5s';
ALTER ROLE agent_ro SET idle_in_transaction_session_timeout = '10s';

-- agent_rw: used only after human approval. No DELETE, no DDL, no users table.
GRANT SELECT, UPDATE ON orders TO agent_rw;
GRANT SELECT, UPDATE ON tickets TO agent_rw;
GRANT SELECT, INSERT ON ticket_comments TO agent_rw;
ALTER ROLE agent_rw SET statement_timeout = '15s';

-- audit_writer: append only
GRANT SELECT, INSERT ON audit_events TO audit_writer;
