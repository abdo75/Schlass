-- 000005_audit_hash_chain.up.sql
-- Spec: docs/specs/audit-log-system.md §4 (REQ-AUD-012, 020, 021, 023).
-- Plan: docs/plans/audit-log.md §M3.
--
-- Make audit_logs tamper-evident. Three pieces:
--   1. A monotonic per-row sequence_no. Sequence default fires inside the
--      same transaction as the INSERT so the value is read back through
--      RETURNING and folded into the row hash.
--   2. A unique (tenant_id, sequence_no) constraint so a tx that races
--      under contention can't produce two rows with the same number.
--      The advisory lock in chain.go is the primary defence; this
--      constraint is the belt-and-suspenders backstop.
--   3. A backfill scheme for rows inserted before M3. We use the SENTINEL
--      approach: legacy rows get prev_hash = NULL and a deterministic
--      legacy row_hash = sha256(BYTEA('legacy:' || id::text)). The
--      verifier (internal/audit/Verify) treats any row whose schema_version
--      predates the current SchemaVersion + has the legacy hash shape as
--      "opaque-but-continuous" — it does not try to re-derive the row hash
--      from canonical JSON for those rows. Continuity proofs only kick in
--      from the first M3-emitted row onward.
--
--      This avoids two failure modes:
--      (a) re-deriving canonical JSON in SQL would have to byte-match
--          internal/audit/canonical.go's NFC + JCS implementation, which
--          is a multi-language correctness hazard for one-time backfill.
--      (b) writing a Go-only backfill in migration code would couple the
--          migration runner to the audit package, which it does not
--          currently import.
--
--      Backfill cost is O(N) on existing rows, single-pass.
--
-- Down migration drops the unique constraint + the sequence; the columns
-- themselves were added in M1 and stay (M1's down drops them).

-- pgcrypto provides digest(bytea, text). Required for the sentinel
-- legacy row_hash backfill below. Loading is idempotent.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Sequence shared across tenants. The constraint pairs sequence_no with
-- tenant_id so per-tenant chains stay independently verifiable; the
-- sequence's job is just monotonic uniqueness within a single instance.
CREATE SEQUENCE audit_logs_seq AS BIGINT MINVALUE 1 NO CYCLE;

-- Backfill any pre-M3 rows in stable insertion order BEFORE the column
-- is set NOT NULL. Order key: created_at, id — created_at is stable
-- per-row and id is the tiebreaker for rows inserted in the same
-- microsecond. Each row gets the next sequence value.
WITH ordered AS (
    SELECT id, ROW_NUMBER() OVER (ORDER BY created_at, id) AS rn
    FROM audit_logs
)
UPDATE audit_logs a
   SET sequence_no = (SELECT nextval('audit_logs_seq') + ordered.rn - 1
                      FROM ordered WHERE ordered.id = a.id)
 WHERE sequence_no IS NULL;

-- After the bulk UPDATE the sequence is at 1 (we only consumed one nextval
-- before adding rn-1). Advance it past the highest assigned sequence_no so
-- the post-migration default fires above every backfilled row.
SELECT setval('audit_logs_seq',
              COALESCE((SELECT MAX(sequence_no) FROM audit_logs), 0) + 1,
              false);

-- Sentinel legacy hashes. Legacy rows get a deterministic but opaque
-- row_hash derived from id alone; prev_hash stays NULL so the verifier
-- knows the chain pre-M3 was not protected. New M3 emits will read the
-- last row's row_hash and link cleanly.
UPDATE audit_logs
   SET row_hash = digest('legacy:' || id::text, 'sha256')
 WHERE row_hash IS NULL;

-- Now make sequence_no NOT NULL and wire its default for future inserts.
ALTER TABLE audit_logs
    ALTER COLUMN sequence_no SET NOT NULL,
    ALTER COLUMN sequence_no SET DEFAULT nextval('audit_logs_seq');

-- Per-tenant uniqueness backstop. Concurrent emits in the same tenant
-- are serialised by pg_advisory_xact_lock(hashtext(tenant_id)) at the
-- chain.go layer; this constraint catches any code path that bypasses
-- the lock (test scaffolding, future alternative writers).
ALTER TABLE audit_logs
    ADD CONSTRAINT audit_logs_seq_unique UNIQUE (tenant_id, sequence_no);

-- schlass_app needs USAGE on the sequence so chain.Append can call
-- nextval() inside the per-tenant advisory lock. Append-only contract
-- for audit_logs is preserved — the role still has only SELECT+INSERT
-- on the table, and no UPDATE/DELETE.
GRANT USAGE ON SEQUENCE audit_logs_seq TO schlass_app;
