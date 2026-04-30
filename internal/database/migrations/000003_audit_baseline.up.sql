-- 000003_audit_baseline.up.sql
-- Spec: docs/specs/audit-log-system.md §3 (REQ-AUD-010, REQ-AUD-062, REQ-AUD-008).
-- Brings audit_logs to the spec's column delta. M2 will drop actor_email and
-- coarsen ip_address; that work stays separate so the M2 backfill is auditable
-- on its own. M3 populates sequence_no/prev_hash/row_hash; left nullable here.

ALTER TABLE audit_logs
    ADD COLUMN schema_version    INT          NOT NULL DEFAULT 1,
    ADD COLUMN recorded_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    ADD COLUMN event_timestamp   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    ADD COLUMN reason_code       TEXT,
    ADD COLUMN actor_type        TEXT         NOT NULL DEFAULT 'user'
        CHECK (actor_type IN ('user', 'service', 'system', 'anonymous')),
    ADD COLUMN actor_session_id  UUID,
    -- Single-tenant deployments use this fixed constant. Multi-tenant
    -- deployments override per-row at emit time once tenancy is wired.
    ADD COLUMN tenant_id         UUID         NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    ADD COLUMN source_service    TEXT         NOT NULL DEFAULT 'unknown',
    ADD COLUMN client_ua_family  TEXT,
    ADD COLUMN client_geo_coarse TEXT,
    ADD COLUMN request_id        TEXT,
    ADD COLUMN correlation_id    UUID,
    -- Hash-chain columns. M3 populates these in-tx via pg_advisory_xact_lock;
    -- leaving nullable here so the table accepts new inserts before M3 lands.
    ADD COLUMN sequence_no       BIGINT,
    ADD COLUMN prev_hash         BYTEA,
    ADD COLUMN row_hash          BYTEA;

-- Backfill event_timestamp from created_at for existing rows so the new
-- column matches the historical insertion time of each row.
UPDATE audit_logs SET event_timestamp = created_at;

-- Best-effort source_service backfill keyed off event_type prefix. Anything
-- that doesn't match falls back to 'unknown' (column default).
UPDATE audit_logs SET source_service = CASE
    WHEN event_type LIKE 'oidc.%'         THEN 'authserver'
    WHEN event_type LIKE 'login.%'        THEN 'auth'
    WHEN event_type LIKE 'logout.%'       THEN 'auth'
    WHEN event_type LIKE 'auth.%'         THEN 'auth'
    WHEN event_type LIKE 'mfa.%'          THEN 'auth'
    WHEN event_type LIKE 'password.%'     THEN 'auth'
    WHEN event_type LIKE 'password_reset.%' THEN 'auth'
    WHEN event_type LIKE 'session.%'      THEN 'auth'
    WHEN event_type LIKE 'account.%'      THEN 'auth'
    WHEN event_type LIKE 'user.%'         THEN 'users'
    WHEN event_type LIKE 'client.%'       THEN 'clients'
    WHEN event_type LIKE 'config.%'       THEN 'instanceconfig'
    WHEN event_type LIKE 'audit.%'        THEN 'audit'
    WHEN event_type LIKE 'setup.%'        THEN 'server'
    ELSE 'unknown'
END;

-- Widen outcome CHECK to admit 'denied'. The original column-level CHECK was
-- created without an explicit name; Postgres assigned 'audit_logs_outcome_check'.
ALTER TABLE audit_logs
    DROP CONSTRAINT audit_logs_outcome_check,
    ADD CONSTRAINT audit_logs_outcome_check
        CHECK (outcome IN ('success', 'failure', 'denied'));
