-- 000008_audit_partitioning.down.sql
-- M5 down is destructive of partition boundary metadata. Audit data
-- round-trips into a plain audit_logs table, but partition names and
-- ranges are intentionally not preserved.

ALTER TABLE audit_logs RENAME TO audit_logs_partitioned;
ALTER TABLE audit_logs_partitioned RENAME CONSTRAINT audit_logs_pkey TO audit_logs_partitioned_pkey;
ALTER TABLE audit_logs_partitioned RENAME CONSTRAINT audit_logs_seq_unique TO audit_logs_partitioned_seq_unique;
ALTER INDEX IF EXISTS idx_audit_logs_actor_id RENAME TO idx_audit_logs_partitioned_actor_id;
ALTER INDEX IF EXISTS idx_audit_logs_created_at RENAME TO idx_audit_logs_partitioned_created_at;
ALTER INDEX IF EXISTS idx_audit_logs_event_type RENAME TO idx_audit_logs_partitioned_event_type;
ALTER INDEX IF EXISTS idx_audit_logs_client_id RENAME TO idx_audit_logs_partitioned_client_id;
ALTER INDEX IF EXISTS idx_audit_logs_event_timestamp RENAME TO idx_audit_logs_partitioned_event_timestamp;

CREATE TABLE audit_logs (
    LIKE audit_logs_partitioned
    INCLUDING DEFAULTS
    INCLUDING GENERATED
    INCLUDING IDENTITY
    INCLUDING STORAGE
    INCLUDING COMMENTS
    INCLUDING COMPRESSION
    INCLUDING STATISTICS
    INCLUDING CONSTRAINTS
);

ALTER TABLE audit_logs
    DROP CONSTRAINT IF EXISTS audit_logs_pkey,
    DROP CONSTRAINT IF EXISTS audit_logs_seq_unique;

ALTER TABLE audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id),
    ADD CONSTRAINT audit_logs_seq_unique UNIQUE (tenant_id, sequence_no);

CREATE INDEX idx_audit_logs_actor_id ON audit_logs(actor_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_client_id ON audit_logs(client_id);

ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY audit_logs_select ON audit_logs
    FOR SELECT USING (true);

CREATE POLICY audit_logs_insert ON audit_logs
    FOR INSERT WITH CHECK (true);

REVOKE UPDATE, DELETE ON audit_logs FROM PUBLIC;
GRANT SELECT, INSERT ON audit_logs TO schlass_app;

INSERT INTO audit_logs
SELECT * FROM audit_logs_partitioned;

DROP TABLE audit_logs_partitioned CASCADE;

ALTER TABLE audit_logs
    DROP CONSTRAINT IF EXISTS audit_logs_retention_bucket_check,
    DROP COLUMN IF EXISTS retention_bucket;

CREATE OR REPLACE FUNCTION audit_log_pseudonymize_user(p_user_id UUID)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    updated_count INTEGER;
BEGIN
    UPDATE audit_logs
    SET actor_id = NULL,
        metadata = jsonb_set(
            COALESCE(metadata, '{}'::jsonb),
            '{pseudonymized_at}',
            to_jsonb(now()),
            true
        )
    WHERE actor_id = p_user_id
      AND (metadata->>'pseudonymized_at') IS NULL;
    GET DIAGNOSTICS updated_count = ROW_COUNT;
    RETURN updated_count;
END;
$$;

REVOKE ALL ON FUNCTION audit_log_pseudonymize_user(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_log_pseudonymize_user(UUID) TO schlass_app;

DELETE FROM instance_config
 WHERE key IN (
    'audit.retention.security_hot_days',
    'audit.retention.security_cold_years',
    'audit.retention.operational_days',
    'audit.cold_tier.backend'
 );
