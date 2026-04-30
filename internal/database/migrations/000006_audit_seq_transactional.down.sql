-- 000006_audit_seq_transactional.down.sql
-- Reverse of 000006: restore the column DEFAULT. After down-migration
-- chain.Append will continue to set sequence_no explicitly, so the
-- DEFAULT is dormant on the in-app write path; it only matters for
-- alternative writers (test scaffolding, manual SQL inserts).

ALTER TABLE audit_logs
    ALTER COLUMN sequence_no SET DEFAULT nextval('audit_logs_seq');
