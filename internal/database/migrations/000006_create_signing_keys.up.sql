CREATE TABLE signing_keys (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    algorithm               TEXT NOT NULL DEFAULT 'RS256',
    public_key_pem          TEXT NOT NULL,
    private_key_encrypted   BYTEA NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'active'
                                CHECK (status IN ('active', 'retiring', 'retired')),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at              TIMESTAMPTZ
);
