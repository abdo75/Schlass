-- 000010_audit_purge_runner_role.up.sql
-- Privilege model: schlass_app cannot purge audit partitions. Only the
-- audit-purge CLI's dedicated audit_purge_runner login role can EXECUTE the
-- SECURITY DEFINER purge function, keeping DETACH/DROP outside the app path.
-- Init scripts create the role with a fixed-but-rotatable local password.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_purge_runner') THEN
        CREATE ROLE audit_purge_runner WITH LOGIN PASSWORD 'audit_purge_runner';
    END IF;
END;
$$;

DO $$
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO audit_purge_runner', current_database());
END;
$$;
GRANT USAGE ON SCHEMA public TO audit_purge_runner;
GRANT SELECT ON TABLE instance_config TO audit_purge_runner;
GRANT SELECT, INSERT ON TABLE audit_logs TO audit_purge_runner;
GRANT SELECT, INSERT ON TABLE audit_anchors TO audit_purge_runner;
GRANT EXECUTE ON FUNCTION audit_purge_expired(TEXT, TEXT) TO audit_purge_runner;
REVOKE EXECUTE ON FUNCTION audit_purge_expired(TEXT, TEXT) FROM schlass_app, PUBLIC;

DO $$
DECLARE
    part REGCLASS;
BEGIN
    FOR part IN
        SELECT relid
          FROM pg_partition_tree('audit_logs'::regclass)
         WHERE relid <> 'audit_logs'::regclass
    LOOP
        EXECUTE format('GRANT SELECT, INSERT ON TABLE %s TO audit_purge_runner', part);
    END LOOP;
END;
$$;
