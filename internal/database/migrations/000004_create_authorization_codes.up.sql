CREATE TABLE authorization_codes (
    code_hash               TEXT PRIMARY KEY,
    client_id               UUID NOT NULL REFERENCES clients(id),
    user_id                 UUID NOT NULL REFERENCES users(id),
    redirect_uri            TEXT NOT NULL,
    scopes                  TEXT[] NOT NULL,
    nonce                   TEXT,
    code_challenge          TEXT NOT NULL,
    code_challenge_method   TEXT NOT NULL DEFAULT 'S256'
                                CHECK (code_challenge_method = 'S256'),
    expires_at              TIMESTAMPTZ NOT NULL,
    used                    BOOLEAN NOT NULL DEFAULT false,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
