-- 000004_audit_pii_closure.down.sql
-- Reverses the column shape change in 000004_audit_pii_closure.up.sql but
-- CANNOT restore destroyed data:
--   * actor_email column is re-added empty. Plaintext emails dropped on
--     the way up are gone forever.
--   * ip_address column is renamed back, but per-host bits zeroed by the
--     forward migration's UPDATE cannot be reconstructed.
-- Operators rolling back must accept this loss.

ALTER TABLE audit_logs RENAME COLUMN client_ip_coarse TO ip_address;

ALTER TABLE audit_logs ADD COLUMN actor_email TEXT;

-- Restore the pre-M2 pseudonymization function body. Rows pseudonymized
-- under the M2 shape (actor_id NULL + metadata.pseudonymized_at set)
-- remain unchanged; this function's pre-M2 contract was a no-op for them
-- since actor_id had already been used as the lookup key.
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
    SET actor_email = 'deleted:' || p_user_id::TEXT
    WHERE actor_id = p_user_id
      AND actor_email IS DISTINCT FROM 'deleted:' || p_user_id::TEXT;
    GET DIAGNOSTICS updated_count = ROW_COUNT;
    RETURN updated_count;
END;
$$;

GRANT EXECUTE ON FUNCTION audit_log_pseudonymize_user(UUID) TO schlass_app;

DELETE FROM instance_config WHERE key = 'audit.client_ip_mode';
