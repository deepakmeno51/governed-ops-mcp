-- Day 1 schema. Moves to Alembic on Day 2.

CREATE TABLE users (
    id            integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email         text NOT NULL UNIQUE,
    full_name     text NOT NULL,
    phone         text,
    password_hash text NOT NULL,
    api_key       text NOT NULL,
    plan          text NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'pro', 'enterprise')),
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE orders (
    id          integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     integer NOT NULL REFERENCES users(id),
    status      text NOT NULL CHECK (status IN ('pending', 'processing', 'paid', 'shipped', 'cancelled', 'failed')),
    total_cents integer NOT NULL CHECK (total_cents >= 0),
    currency    char(3) NOT NULL DEFAULT 'USD',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX orders_user_id_idx ON orders (user_id);
CREATE INDEX orders_status_idx  ON orders (status);

CREATE TABLE app_logs (
    id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts       timestamptz NOT NULL,
    service  text NOT NULL,
    level    text NOT NULL CHECK (level IN ('DEBUG', 'INFO', 'WARN', 'ERROR')),
    message  text NOT NULL,
    trace_id uuid
);
CREATE INDEX app_logs_ts_idx         ON app_logs (ts DESC);
CREATE INDEX app_logs_service_ts_idx ON app_logs (service, ts DESC);

CREATE TABLE tickets (
    id          integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    title       text NOT NULL,
    description text NOT NULL,
    status      text NOT NULL CHECK (status IN ('open', 'investigating', 'resolved', 'closed')),
    severity    text NOT NULL CHECK (severity IN ('sev1', 'sev2', 'sev3')),
    service     text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tickets_status_idx ON tickets (status);

CREATE TABLE ticket_comments (
    id         integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ticket_id  integer NOT NULL REFERENCES tickets(id),
    author     text NOT NULL,
    body       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ticket_comments_ticket_idx ON ticket_comments (ticket_id);

CREATE TABLE approvals (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tool_name       text NOT NULL,
    args            jsonb NOT NULL,
    args_hash       char(64) NOT NULL,          -- SHA-256 of canonical tool + args
    requester       text NOT NULL,
    status          text NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'EXECUTED')),
    idempotency_key text NOT NULL UNIQUE,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    decided_by      text,
    decided_at      timestamptz,
    executed_at     timestamptz,
    result          jsonb,
    CONSTRAINT approver_not_requester CHECK (decided_by IS NULL OR decided_by <> requester),
    CONSTRAINT decision_has_decider   CHECK (status IN ('PENDING', 'EXPIRED') OR decided_by IS NOT NULL)
);
CREATE INDEX approvals_status_expiry_idx ON approvals (status, expires_at);

CREATE TABLE audit_events (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts              timestamptz NOT NULL DEFAULT now(),
    actor           text NOT NULL,
    event_type      text NOT NULL,              -- TOOL_CALL, APPROVAL_CREATED, APPROVAL_DECIDED, EXECUTED, ...
    tool_name       text,
    risk_tier       smallint CHECK (risk_tier BETWEEN 1 AND 3),
    args            jsonb,
    agent_reasoning text,                       -- written by the agent: untrusted
    approval_id     uuid REFERENCES approvals(id),
    outcome         text,
    output          jsonb,
    prev_hash       char(64),
    row_hash        char(64) NOT NULL
);
CREATE INDEX audit_events_ts_idx ON audit_events (ts);
