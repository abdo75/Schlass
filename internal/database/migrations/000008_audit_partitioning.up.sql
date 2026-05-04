-- 000008_audit_partitioning.up.sql
-- Spec: REQ-AUD-032/033 and docs/specs/audit-log-system.md §13.4.
-- Recreates audit_logs as RANGE-partitioned by event_timestamp, then adds
-- retention_bucket and extends GDPR pseudonymization to target_id.

ALTER TABLE audit_logs RENAME TO audit_logs_old;
ALTER TABLE audit_logs_old RENAME CONSTRAINT audit_logs_pkey TO audit_logs_old_pkey;
ALTER TABLE audit_logs_old RENAME CONSTRAINT audit_logs_seq_unique TO audit_logs_old_seq_unique;
ALTER INDEX IF EXISTS idx_audit_logs_actor_id RENAME TO idx_audit_logs_old_actor_id;
ALTER INDEX IF EXISTS idx_audit_logs_created_at RENAME TO idx_audit_logs_old_created_at;
ALTER INDEX IF EXISTS idx_audit_logs_event_type RENAME TO idx_audit_logs_old_event_type;
ALTER INDEX IF EXISTS idx_audit_logs_client_id RENAME TO idx_audit_logs_old_client_id;

CREATE TABLE audit_logs (
    LIKE audit_logs_old
    INCLUDING DEFAULTS
    INCLUDING GENERATED
    INCLUDING IDENTITY
    INCLUDING STORAGE
    INCLUDING COMMENTS
    INCLUDING COMPRESSION
    INCLUDING STATISTICS
    INCLUDING CONSTRAINTS
) PARTITION BY RANGE (event_timestamp);

-- Partitioned UNIQUE/PRIMARY KEY constraints must include the partition key.
-- M5 therefore widens PK id -> (id, event_timestamp) and M3's unique
-- (tenant_id, sequence_no) -> (tenant_id, sequence_no, event_timestamp).
ALTER TABLE audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id, event_timestamp),
    ADD CONSTRAINT audit_logs_seq_unique UNIQUE (tenant_id, sequence_no, event_timestamp);

CREATE INDEX idx_audit_logs_actor_id ON audit_logs(actor_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_client_id ON audit_logs(client_id);
CREATE INDEX idx_audit_logs_event_timestamp ON audit_logs(event_timestamp);

ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY audit_logs_select ON audit_logs
    FOR SELECT USING (true);

CREATE POLICY audit_logs_insert ON audit_logs
    FOR INSERT WITH CHECK (true);

REVOKE UPDATE, DELETE ON audit_logs FROM PUBLIC;
GRANT SELECT, INSERT ON audit_logs TO schlass_app;

DO $$
DECLARE
    month_start DATE := date_trunc('month', now())::date;
    part_start DATE;
    part_name TEXT;
BEGIN
    FOR i IN 0..12 LOOP
        part_start := month_start - (i || ' months')::interval;
        part_name := 'audit_logs_' || to_char(part_start, 'YYYYMM');
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_logs FOR VALUES FROM (%L) TO (%L)',
            part_name,
            part_start,
            (part_start + interval '1 month')::date
        );
        EXECUTE format('GRANT SELECT, INSERT ON TABLE %I TO schlass_app', part_name);
        EXECUTE format('REVOKE UPDATE, DELETE ON TABLE %I FROM PUBLIC', part_name);
    END LOOP;
END;
$$;

INSERT INTO audit_logs (
    id, event_type, actor_id, target_type, target_id, client_id,
    outcome, metadata, created_at, schema_version, recorded_at,
    event_timestamp, reason_code, actor_type, actor_session_id,
    tenant_id, source_service, client_ua_family, client_geo_coarse,
    request_id, correlation_id, sequence_no, prev_hash, row_hash,
    client_ip_coarse
)
SELECT
    id, event_type, actor_id, target_type, target_id, client_id,
    outcome, metadata, created_at, schema_version, recorded_at,
    event_timestamp, reason_code, actor_type, actor_session_id,
    tenant_id, source_service, client_ua_family, client_geo_coarse,
    request_id, correlation_id, sequence_no, prev_hash, row_hash,
    client_ip_coarse
FROM audit_logs_old;

DROP TABLE audit_logs_old;

ALTER TABLE audit_logs
    ADD COLUMN retention_bucket TEXT NOT NULL DEFAULT 'security',
    ADD CONSTRAINT audit_logs_retention_bucket_check
        CHECK (retention_bucket IN ('security', 'operational'));

UPDATE audit_logs
   SET retention_bucket = CASE
       WHEN event_type LIKE 'session.%'
         OR event_type LIKE 'ratelimit.%'
         OR event_type LIKE 'system.%'
         OR event_type IN (
             'password_reset.cleanup_swept',
             'oidc.userinfo.accessed',
             'client.created',
             'client.disabled',
             'client.enabled',
             'client.grants_updated',
             'client.name_updated',
             'client.redirect_uris_updated',
             'client.scopes_updated',
             'user.created',
             'user.enabled',
             'user.updated',
             'audit.viewed'
         )
       THEN 'operational'
       ELSE 'security'
   END;

CREATE OR REPLACE FUNCTION audit_log_pseudonymize_user(p_user_id UUID)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    actor_count INTEGER;
    target_count INTEGER;
BEGIN
    UPDATE audit_logs
    SET actor_id = NULL,
        metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object('pseudonymized_at', now())
    WHERE actor_id = p_user_id
      AND (metadata->>'pseudonymized_at') IS NULL;
    GET DIAGNOSTICS actor_count = ROW_COUNT;

    UPDATE audit_logs
    SET target_id = NULL,
        metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object('pseudonymized_at', now())
    WHERE target_id = p_user_id::text;
    GET DIAGNOSTICS target_count = ROW_COUNT;

    RETURN actor_count + target_count;
END;
$$;

REVOKE ALL ON FUNCTION audit_log_pseudonymize_user(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_log_pseudonymize_user(UUID) TO schlass_app;

INSERT INTO instance_config (key, value) VALUES
    ('audit.retention.security_hot_days',  '365'),
    ('audit.retention.security_cold_years', '6'),
    ('audit.retention.operational_days',   '90'),
    ('audit.cold_tier.backend',            '"same_as_anchor"')
ON CONFLICT (key) DO NOTHING;
