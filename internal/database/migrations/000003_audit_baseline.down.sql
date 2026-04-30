-- 000003_audit_baseline.down.sql
-- Reverse the M1 schema baseline. Re-narrows the outcome CHECK; any rows with
-- outcome='denied' will block this migration (intentional — operator must
-- decide how to triage them rather than silently lose data).

ALTER TABLE audit_logs
    DROP CONSTRAINT audit_logs_outcome_check,
    ADD CONSTRAINT audit_logs_outcome_check
        CHECK (outcome IN ('success', 'failure'));

ALTER TABLE audit_logs
    DROP COLUMN row_hash,
    DROP COLUMN prev_hash,
    DROP COLUMN sequence_no,
    DROP COLUMN correlation_id,
    DROP COLUMN request_id,
    DROP COLUMN client_geo_coarse,
    DROP COLUMN client_ua_family,
    DROP COLUMN source_service,
    DROP COLUMN tenant_id,
    DROP COLUMN actor_session_id,
    DROP COLUMN actor_type,
    DROP COLUMN reason_code,
    DROP COLUMN event_timestamp,
    DROP COLUMN recorded_at,
    DROP COLUMN schema_version;
