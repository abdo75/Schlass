-- 000012_audit_stream_format.up.sql
-- Adds audit.stream.format instance_config key (REQ-AUD-051 / M9).
-- "raw" (default): push stream.Event JSON as before.
-- "caep": filter to events with CAEP URN mappings, project to RFC 8417
--         SET, sign with the active OIDC key, push the JWS string.

INSERT INTO instance_config (key, value)
    VALUES ('audit.stream.format', '"raw"')
ON CONFLICT (key) DO NOTHING;
