-- 000009_audit_purge_role.up.sql
-- by the Go purge job. audit_purge receives DELETE only on partition tables,
-- never on the partitioned parent. The SECURITY DEFINER function stays owned
-- by the migration/table owner because PostgreSQL requires owner-level
-- privileges for DETACH PARTITION and DROP TABLE.

CREATE ROLE audit_purge NOLOGIN;

CREATE OR REPLACE FUNCTION audit_purge_expired(
    p_partition_name TEXT,
    p_action TEXT
)
RETURNS TABLE(partition_name TEXT, action TEXT, rows_affected BIGINT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    rel REGCLASS;
    n BIGINT := 0;
BEGIN
    IF p_partition_name IS NULL OR p_partition_name !~ '^audit_logs_[0-9]{6}$' THEN
        RAISE EXCEPTION 'invalid audit partition name: %', p_partition_name;
    END IF;
    IF p_action NOT IN ('detach_drop', 'drop_operational') THEN
        RAISE EXCEPTION 'invalid audit purge action: %', p_action;
    END IF;

    SELECT to_regclass(p_partition_name) INTO rel;
    IF rel IS NULL THEN
        RAISE EXCEPTION 'audit partition does not exist: %', p_partition_name;
    END IF;

    EXECUTE format('SELECT count(*) FROM %s', rel) INTO n;
    EXECUTE format('ALTER TABLE audit_logs DETACH PARTITION %s', rel);
    EXECUTE format('DROP TABLE %s', rel);

    partition_name := p_partition_name;
    action := p_action;
    rows_affected := n;
    RETURN NEXT;
END;
$$;

GRANT EXECUTE ON FUNCTION audit_purge_expired(TEXT, TEXT) TO schlass_app;

DO $$
DECLARE
    part REGCLASS;
BEGIN
    FOR part IN
        SELECT relid
          FROM pg_partition_tree('audit_logs'::regclass)
         WHERE relid <> 'audit_logs'::regclass
    LOOP
        EXECUTE format('GRANT DELETE ON TABLE %s TO audit_purge', part);
    END LOOP;
END;
$$;
