-- 000005_audit_hash_chain.down.sql
-- Reverse of M3 hash-chain wiring. Drops the unique constraint, releases
-- the sequence default, and drops the sequence. Hash-chain columns
-- (sequence_no, prev_hash, row_hash) themselves were created by M1 and
-- are dropped by M1's down migration; we leave them in place here.
--
-- pgcrypto is left loaded — other migrations may rely on it, and DROP
-- EXTENSION here would couple the two milestones. Operators who need a
-- truly clean revert can drop the extension manually.

ALTER TABLE audit_logs
    DROP CONSTRAINT IF EXISTS audit_logs_seq_unique;

ALTER TABLE audit_logs
    ALTER COLUMN sequence_no DROP DEFAULT,
    ALTER COLUMN sequence_no DROP NOT NULL;

DROP SEQUENCE IF EXISTS audit_logs_seq;
