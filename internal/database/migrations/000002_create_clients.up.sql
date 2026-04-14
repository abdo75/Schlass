CREATE TABLE clients (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                        TEXT NOT NULL,
    client_type                 TEXT NOT NULL
                                    CHECK (client_type IN ('confidential', 'public')),
    secret_hash                 TEXT,
    redirect_uris               TEXT[] NOT NULL,
    allowed_grant_types         TEXT[] NOT NULL,
    allowed_scopes              TEXT[] NOT NULL,
    token_endpoint_auth_method  TEXT NOT NULL
                                    CHECK (token_endpoint_auth_method IN ('client_secret_post', 'none')),
    status                      TEXT NOT NULL DEFAULT 'active'
                                    CHECK (status IN ('active', 'disabled')),
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT confidential_requires_secret CHECK (
        (client_type = 'public' AND secret_hash IS NULL) OR
        (client_type = 'confidential' AND secret_hash IS NOT NULL)
    )
);
