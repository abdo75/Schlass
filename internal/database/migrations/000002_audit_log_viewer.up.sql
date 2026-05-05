-- 000002_audit_log_viewer.up.sql
-- Two new instance_config keys for the audit-log viewer (Sprint 7).
-- Audit permissions are added in Go (rolePermissions map), not here.
-- audit_viewed_in_session is a Valkey Session field, not a SQL column.

INSERT INTO instance_config (key, value)
VALUES
  ('audit_view_logging_enabled', 'true'),
  ('audit_export_max_rows', '50000')
ON CONFLICT (key) DO NOTHING;
