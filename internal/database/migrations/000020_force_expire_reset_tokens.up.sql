-- Force-expire all outstanding password-reset tokens because the token_hash
-- format changed from SHA-256 to HMAC-SHA256 with an HKDF-derived pepper.
-- Plaintext tokens are unrecoverable so we cannot re-hash existing rows.
-- Users with outstanding links (<=30min TTL) re-request.
UPDATE password_reset_tokens
   SET used_at = now()
 WHERE used_at IS NULL;
