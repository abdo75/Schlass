-- GDPR Art. 17 pseudonymization bridge for audit_logs.
--
-- audit_logs is append-only to schlass_app (UPDATE + DELETE revoked in
-- migration 000007; SELECT + INSERT granted in 000010). Art. 17 requires
-- scrubbing PII on valid erasure request, which forces a bounded exception.
-- Rather than grant schlass_app UPDATE (which would let any code path mutate
-- the column), we expose a single SECURITY DEFINER function owned by the
-- migration role that can only replace actor_email with 'deleted:<uuid>'
-- on rows matching the given user id. schlass_app has EXECUTE on this
-- function only; it still has no direct UPDATE on the table.
--
-- See docs/superpowers/specs/2026-04-19-sprint6-hardening-design.md §M4.

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

REVOKE ALL ON FUNCTION audit_log_pseudonymize_user(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_log_pseudonymize_user(UUID) TO schlass_app;
