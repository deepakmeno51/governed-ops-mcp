-- Day 10: record when an execution started, so an execution that never finished can be detected and closed.
--   started_at is set only by the APPROVED -> EXECUTING claim and never changes afterwards.
-- An execution is stale when it is EXECUTING for longer than EXECUTION_STALE_SECONDS. A recovery job
-- (ops_executor) then marks it FAILED. Rule unchanged: only ops_executor may move EXECUTING -> FAILED.

ALTER TABLE approvals ADD COLUMN started_at timestamptz;
GRANT UPDATE (started_at) ON approvals TO ops_executor;

CREATE OR REPLACE FUNCTION approvals_guard() RETURNS trigger
LANGUAGE plpgsql AS $f$
DECLARE
  actor text := session_user;
  is_decision boolean := false;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'PENDING' OR NEW.decided_by IS NOT NULL OR NEW.decided_at IS NOT NULL
       OR NEW.executed_at IS NOT NULL OR NEW.result IS NOT NULL OR NEW.started_at IS NOT NULL THEN
      RAISE EXCEPTION USING MESSAGE = 'approvals must be created as PENDING', ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.tool_name IS DISTINCT FROM OLD.tool_name
     OR NEW.args IS DISTINCT FROM OLD.args
     OR NEW.args_hash IS DISTINCT FROM OLD.args_hash
     OR NEW.requester IS DISTINCT FROM OLD.requester
     OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.preview IS DISTINCT FROM OLD.preview THEN
    RAISE EXCEPTION USING MESSAGE = 'approval request fields are immutable', ERRCODE = 'check_violation';
  END IF;

  IF OLD.status = NEW.status THEN
    IF NEW.decided_by IS DISTINCT FROM OLD.decided_by OR NEW.decided_at IS DISTINCT FROM OLD.decided_at
       OR NEW.executed_at IS DISTINCT FROM OLD.executed_at OR NEW.result IS DISTINCT FROM OLD.result
       OR NEW.started_at IS DISTINCT FROM OLD.started_at THEN
      RAISE EXCEPTION USING MESSAGE = 'approval fields change only with a state transition', ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.status = 'PENDING' AND NEW.status IN ('APPROVED', 'REJECTED') THEN
    is_decision := true;
    IF actor <> 'approval_decider' THEN
      RAISE EXCEPTION USING MESSAGE = 'only approval_decider may approve or reject', ERRCODE = 'insufficient_privilege';
    END IF;
    IF OLD.expires_at <= now() THEN
      RAISE EXCEPTION USING MESSAGE = 'approval has expired', ERRCODE = 'check_violation';
    END IF;
    IF NEW.decided_by IS NULL OR NEW.decided_at IS NULL THEN
      RAISE EXCEPTION USING MESSAGE = 'a decision needs decided_by and decided_at', ERRCODE = 'check_violation';
    END IF;
  ELSIF OLD.status IN ('PENDING', 'APPROVED') AND NEW.status = 'EXPIRED' THEN
    IF actor NOT IN ('ops_executor', 'approval_decider') THEN
      RAISE EXCEPTION USING MESSAGE = 'not allowed to expire approvals', ERRCODE = 'insufficient_privilege';
    END IF;
    IF OLD.expires_at > now() THEN
      RAISE EXCEPTION USING MESSAGE = 'approval has not expired yet', ERRCODE = 'check_violation';
    END IF;
  ELSIF OLD.status = 'APPROVED' AND NEW.status = 'EXECUTING' THEN
    IF actor <> 'ops_executor' THEN
      RAISE EXCEPTION USING MESSAGE = 'only ops_executor may execute', ERRCODE = 'insufficient_privilege';
    END IF;
    IF NEW.started_at IS NULL THEN
      RAISE EXCEPTION USING MESSAGE = 'starting an execution needs started_at', ERRCODE = 'check_violation';
    END IF;
    IF OLD.expires_at <= now() THEN
      RAISE EXCEPTION USING MESSAGE = 'approval has expired', ERRCODE = 'check_violation';
    END IF;
  ELSIF OLD.status = 'EXECUTING' AND NEW.status IN ('EXECUTED', 'FAILED') THEN
    IF actor <> 'ops_executor' THEN
      RAISE EXCEPTION USING MESSAGE = 'only ops_executor may finish an execution', ERRCODE = 'insufficient_privilege';
    END IF;
  ELSE
    RAISE EXCEPTION USING MESSAGE = 'illegal approval state change: ' || OLD.status || ' to ' || NEW.status,
                          ERRCODE = 'check_violation';
  END IF;

  IF NOT (OLD.status = 'APPROVED' AND NEW.status = 'EXECUTING') AND NEW.started_at IS DISTINCT FROM OLD.started_at THEN
    RAISE EXCEPTION USING MESSAGE = 'started_at is set only when an execution starts', ERRCODE = 'check_violation';
  END IF;

  IF NOT is_decision AND (NEW.decided_by IS DISTINCT FROM OLD.decided_by OR NEW.decided_at IS DISTINCT FROM OLD.decided_at) THEN
    RAISE EXCEPTION USING MESSAGE = 'decision fields cannot change after the decision', ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$f$;
