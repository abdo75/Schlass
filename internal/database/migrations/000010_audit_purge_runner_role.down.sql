-- 000010_audit_purge_runner_role.down.sql
-- Restore the M5 pre-fixup EXECUTE grant so down/up round trips reproduce the
-- previous migration state before 000010 is re-applied.

REVOKE EXECUTE ON FUNCTION audit_purge_expired(TEXT, TEXT) FROM audit_purge_runner, PUBLIC;
REVOKE SELECT ON TABLE instance_config FROM audit_purge_runner;
REVOKE SELECT, INSERT ON TABLE audit_logs FROM audit_purge_runner;
REVOKE SELECT, INSERT ON TABLE audit_anchors FROM audit_purge_runner;
REVOKE USAGE ON SCHEMA public FROM audit_purge_runner;
DO $$
BEGIN
    EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM audit_purge_runner', current_database());
END;
$$;
DO $$
DECLARE
    part REGCLASS;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_purge_runner') THEN
        FOR part IN
            SELECT relid
              FROM pg_partition_tree('audit_logs'::regclass)
             WHERE relid <> 'audit_logs'::regclass
        LOOP
            EXECUTE format('REVOKE SELECT, INSERT ON TABLE %s FROM audit_purge_runner', part);
        END LOOP;
    END IF;
END;
$$;
GRANT EXECUTE ON FUNCTION audit_purge_expired(TEXT, TEXT) TO schlass_app;
-- Do not DROP ROLE here: packaged init scripts may have created the login
-- role before migrations, in which case the migration role lacks ADMIN OPTION
-- on it. Revoking privileges is sufficient for a down migration.
