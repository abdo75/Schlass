-- 000006_audit_seq_transactional.up.sql
-- Spec: docs/specs/audit-log-system.md §4 (REQ-AUD-021).
-- Plan: docs/plans/audit-log.md §M3 Step 6 — "sequence_no is contiguous".
--
-- Make sequence_no allocation transactional. The M3 wiring used
-- `nextval('audit_logs_seq')` as the column DEFAULT (and explicitly
-- inside chain.Append). Postgres sequences advance OUTSIDE the
-- enclosing transaction, so a business tx that aborted after
-- chain.Append returned would burn its sequence number. The next
-- committed emit would then carry a non-contiguous sequence_no, and
-- audit.Verify would report a Gap{MissingSequenceNo} — a
-- false-positive tampering alert on an honest chain.
--
-- Fix: chain.Append now computes sequence_no via MAX+1 inside the
-- per-tenant pg_advisory_xact_lock. The lock already serialises
-- concurrent emits per tenant, so the MAX read is race-free, and the
-- MAX read participates in the same tx as the INSERT — a rolled-back
-- tx leaves no sequence-number scar.
--
-- This migration removes the now-misleading column DEFAULT. The
-- sequence object itself is kept (vestigial) for back-compat: existing
-- backfill paths and the M3 down-migration both reference
-- audit_logs_seq by name, and dropping it here would force a
-- co-ordinated change in those callers. It is no longer the source of
-- truth.

ALTER TABLE audit_logs
    ALTER COLUMN sequence_no DROP DEFAULT;
