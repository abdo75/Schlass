DROP POLICY IF EXISTS audit_logs_insert ON audit_logs;
DROP POLICY IF EXISTS audit_logs_select ON audit_logs;
ALTER TABLE audit_logs DISABLE ROW LEVEL SECURITY;
DROP TABLE IF EXISTS audit_logs;
