-- 000011_audit_streaming.down.sql

DELETE FROM instance_config WHERE key IN (
    'audit.stream.backend',
    'audit.stream.endpoint',
    'audit.stream.token_ref',
    'audit.stream.poll_secs',
    'audit.stream.batch_size'
);

DROP INDEX IF EXISTS audit_stream_dlq_due_idx;
DROP TABLE IF EXISTS audit_stream_dlq;
DROP TABLE IF EXISTS audit_stream_state;
