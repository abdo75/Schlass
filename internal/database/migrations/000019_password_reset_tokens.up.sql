-- Password reset tokens. Plaintext token lives only in email/URL; DB
-- stores SHA-256 hash (BYTEA) keyed for lookup. Tokens are single-use
-- (used_at != NULL) and expire after 30 minutes. ON DELETE CASCADE
-- matches authorization_codes — if the user is deleted mid-flow, their
-- outstanding reset tokens vanish with them.

CREATE TABLE password_reset_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   BYTEA NOT NULL UNIQUE,
    expires_at   TIMESTAMPTZ NOT NULL,
    used_at      TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip_address   INET
);

CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON password_reset_tokens TO schlass_app;
