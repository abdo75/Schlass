-- 000011_audit_streaming.up.sql
-- Spec: docs/specs/audit-log-system.md REQ-AUD-050/060/061 + plan §M8.
--
-- Outbound streaming + DLQ. The streamer is a watermark-driven worker
-- that reads audit_logs ahead of audit_stream_state.last_seq and pushes
-- batches to the configured Streamer (syslog RFC 5424 over TCP+TLS or
-- OTLP HTTP/JSON). Failed pushes land in audit_stream_dlq for
-- exponential-backoff retry; rows older than 24h with no success are
-- marked attempt_count = -1 (permanent drop) + emit `audit.stream.dropped`.
--
-- audit_stream_dlq stores only a (tenant_id, sequence_no, audit_id)
-- pointer to the audit_logs row — the worker re-reads the source row on
-- each retry so PII coarsening rules from M2 are not duplicated and
-- can never drift.

CREATE TABLE audit_stream_state (
    tenant_id  UUID PRIMARY KEY,
    last_seq   BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_stream_dlq (
    audit_id      UUID NOT NULL,
    tenant_id     UUID NOT NULL,
    sequence_no   BIGINT NOT NULL,
    attempt_count INT NOT NULL DEFAULT 0,
    last_error    TEXT,
    next_retry_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, sequence_no)
);

-- Index for DLQ retry scan: rows due for retry in sequence order.
CREATE INDEX audit_stream_dlq_due_idx
    ON audit_stream_dlq (tenant_id, next_retry_at)
    WHERE attempt_count >= 0;

REVOKE ALL ON audit_stream_state, audit_stream_dlq FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_stream_state TO schlass_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_stream_dlq TO schlass_app;
-- multi-tenant: future tenant isolation here adds RLS policy keyed on tenant_id.

-- Streaming config defaults. JSONB literals — match the convention in
-- 000007_audit_anchors.up.sql.
INSERT INTO instance_config (key, value) VALUES
    ('audit.stream.backend',    '"none"'),
    ('audit.stream.endpoint',   '""'),
    ('audit.stream.token_ref',  '""'),
    ('audit.stream.poll_secs',  '5'),
    ('audit.stream.batch_size', '100')
ON CONFLICT (key) DO NOTHING;
