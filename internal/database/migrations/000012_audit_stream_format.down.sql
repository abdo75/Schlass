-- 000012_audit_stream_format.down.sql
DELETE FROM instance_config WHERE key = 'audit.stream.format';
