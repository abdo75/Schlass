-- 000004_audit_pii_closure.up.sql
-- Spec: docs/specs/audit-log-system.md §6 PII closure (REQ-AUD-011, 030, 031).
--
-- One-way PII shape change for audit_logs:
--   1. Coarsen historical ip_address rows in place (/24 v4, /48 v6) so
--      no plaintext per-host IP survives the migration.
--   2. Rename ip_address -> client_ip_coarse to match the spec name.
--   3. Drop actor_email entirely. The viewer renders actor display
--      via a live LEFT JOIN on users.email at read time; pseudonymized
--      rows fall back to the literal 'pseudonymized' string.
--   4. Rewrite audit_log_pseudonymize_user. Pre-M2 it set
--      actor_email = 'deleted:<uuid>'. Post-M2 it nulls actor_id and
--      writes a `pseudonymized_at` marker into metadata. Append-only
--      contract preserved (the rows survive; only the actor link is
--      severed).

-- Coarsen v4: zero host bits below /24.
UPDATE audit_logs
   SET ip_address = set_masklen(ip_address::cidr, 24)::cidr::inet
 WHERE ip_address IS NOT NULL
   AND family(ip_address) = 4;

-- Coarsen v6: zero everything below /48.
UPDATE audit_logs
   SET ip_address = set_masklen(ip_address::cidr, 48)::cidr::inet
 WHERE ip_address IS NOT NULL
   AND family(ip_address) = 6;

-- Rename to the spec column name.
ALTER TABLE audit_logs RENAME COLUMN ip_address TO client_ip_coarse;

-- Drop plaintext email column. The function below no longer touches it.
ALTER TABLE audit_logs DROP COLUMN actor_email;

-- Rewrite the pseudonymization function. SECURITY DEFINER + EXECUTE TO
-- schlass_app pattern preserved (grant re-applied below).
CREATE OR REPLACE FUNCTION audit_log_pseudonymize_user(p_user_id UUID)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    updated_count INTEGER;
BEGIN
    UPDATE audit_logs
    SET actor_id = NULL,
        metadata = jsonb_set(
            COALESCE(metadata, '{}'::jsonb),
            '{pseudonymized_at}',
            to_jsonb(now()),
            true
        )
    WHERE actor_id = p_user_id
      AND (metadata->>'pseudonymized_at') IS NULL;
    GET DIAGNOSTICS updated_count = ROW_COUNT;
    RETURN updated_count;
END;
$$;

-- Re-grant to schlass_app. The original grant from migration 000001
-- targeted the prior function body; PL/pgSQL CREATE OR REPLACE keeps the
-- ACL, but restating it here makes intent explicit and survives any
-- DROP/CREATE rewrites in future migrations.
GRANT EXECUTE ON FUNCTION audit_log_pseudonymize_user(UUID) TO schlass_app;

-- Seed the IP coarsening mode knob (coarse | country | off). Default
-- 'coarse' matches REQ-AUD-031. The backend reads this once at startup;
-- the settings handler validates writes against the same enum.
INSERT INTO instance_config (key, value)
VALUES ('audit.client_ip_mode', '"coarse"')
ON CONFLICT (key) DO NOTHING;
