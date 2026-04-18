-- internal/database/migrations/000013_create_totp_recovery_codes_and_counter.up.sql
-- Adds TOTP replay-prevention counter and the recovery-codes table.
-- See docs/superpowers/specs/2026-04-17-totp-mfa-design.md §3a.

ALTER TABLE users
  ADD COLUMN last_used_totp_counter BIGINT NOT NULL DEFAULT 0;

CREATE TABLE totp_recovery_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash BYTEA NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Partial index on unused codes — the fast path during recovery-code login
-- is "list unused codes for this user, verify each against the input hash."
CREATE INDEX idx_totp_recovery_codes_user_unused
  ON totp_recovery_codes (user_id)
  WHERE used_at IS NULL;

-- Same schlass_app privilege pattern as migration 000010.
GRANT SELECT, INSERT, UPDATE, DELETE ON totp_recovery_codes TO schlass_app;
