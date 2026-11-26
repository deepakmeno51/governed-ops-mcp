-- Approval state machine, enforced by the database.
--   PENDING  -> APPROVED | REJECTED      only role approval_decider
--   PENDING | APPROVED -> EXPIRED        only after expires_at, by ops_executor or approval_decider
--   APPROVED -> EXECUTING                only role ops_executor, only before expires_at
--   EXECUTING -> EXECUTED | FAILED       only role ops_executor
-- The request itself (tool, args, hash, requester, expiry, preview) is immutable once created.

ALTER TABLE approvals ADD COLUMN preview jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE approvals DROP CONSTRAINT approvals_status_check;
ALTER TABLE approvals ADD CONSTRAINT approvals_status_check
  CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'EXECUTING', 'EXECUTED', 'FAILED'));

GRANT USAGE ON SCHEMA public TO ops_executor, approval_decider;

-- ops_executor (the MCP server): create requests, claim and finish executions. Cannot approve.
GRANT SELECT, INSERT ON approvals TO ops_executor;
GRANT UPDATE (status, executed_at, result) ON approvals TO ops_executor;
GRANT agent_rw TO ops_executor WITH INHERIT FALSE, SET TRUE;   -- may SET ROLE agent_rw for one transaction
ALTER ROLE ops_executor SET statement_timeout = '20s';

-- approval_decider (the approval UI): read requests, approve or reject. Cannot execute.
GRANT SELECT ON approvals TO approval_decider;
GRANT UPDATE (status, decided_by, decided_at) ON approvals TO approval_decider;
ALTER ROLE approval_decider SET statement_timeout = '5s';

CREATE FUNCTION approvals_guard() RETURNS trigger
LANGUAGE plpgsql AS $f$
DECLARE
  actor text := session_user;
  is_decision boolean := false;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'PENDING' OR NEW.decided_by IS NOT NULL OR NEW.decided_at IS NOT NULL
       OR NEW.executed_at IS NOT NULL OR NEW.result IS NOT NULL THEN
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
       OR NEW.executed_at IS DISTINCT FROM OLD.executed_at OR NEW.result IS DISTINCT FROM OLD.result THEN
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

  IF NOT is_decision AND (NEW.decided_by IS DISTINCT FROM OLD.decided_by OR NEW.decided_at IS DISTINCT FROM OLD.decided_at) THEN
    RAISE EXCEPTION USING MESSAGE = 'decision fields cannot change after the decision', ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$f$;

CREATE TRIGGER approvals_guard_trg
  BEFORE INSERT OR UPDATE ON approvals
  FOR EACH ROW EXECUTE FUNCTION approvals_guard();
