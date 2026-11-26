-- audit_events is append-only. Even the table owner cannot UPDATE, DELETE or TRUNCATE
-- without first dropping or disabling these triggers, and the hash chain exposes any such edit.
CREATE FUNCTION audit_events_immutable() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  RAISE EXCEPTION USING MESSAGE = 'audit_events is append-only: ' || TG_OP || ' blocked',
                        ERRCODE = 'insufficient_privilege';
END
$f$;

CREATE TRIGGER audit_events_no_update_delete
  BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();

CREATE TRIGGER audit_events_no_truncate
  BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION audit_events_immutable();
