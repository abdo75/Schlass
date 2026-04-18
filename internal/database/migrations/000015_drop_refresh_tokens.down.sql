CREATE TABLE refresh_tokens (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash    TEXT NOT NULL UNIQUE,
    user_id       UUID NOT NULL REFERENCES users(id),
    client_id     UUID NOT NULL REFERENCES clients(id),
    scopes        TEXT[] NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    last_used_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON refresh_tokens TO schlass_app;
