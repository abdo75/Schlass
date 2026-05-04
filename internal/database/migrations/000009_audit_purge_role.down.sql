-- 000009_audit_purge_role.down.sql
-- Backout for the purge execution role and SECURITY DEFINER function.

DROP FUNCTION IF EXISTS audit_purge_expired(TEXT, TEXT);
DO $$
DECLARE
    part REGCLASS;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_purge') THEN
        FOR part IN
            SELECT relid
              FROM pg_partition_tree('audit_logs'::regclass)
             WHERE relid <> 'audit_logs'::regclass
        LOOP
            EXECUTE format('REVOKE DELETE ON TABLE %s FROM audit_purge', part);
        END LOOP;
    END IF;
END;
$$;
DROP ROLE IF EXISTS audit_purge;
