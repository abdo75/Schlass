CREATE TABLE users (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                   TEXT NOT NULL,
    password_hash           TEXT NOT NULL,
    role                    TEXT NOT NULL DEFAULT 'user'
                                CHECK (role IN ('super_admin', 'user')),
    status                  TEXT NOT NULL DEFAULT 'active'
                                CHECK (status IN ('active', 'disabled')),
    force_password_change   BOOLEAN NOT NULL DEFAULT true,
    totp_secret_encrypted   BYTEA,
    totp_enrolled_at        TIMESTAMPTZ,
    failed_login_attempts   INT NOT NULL DEFAULT 0,
    locked_until            TIMESTAMPTZ,
    last_used_totp_counter  BIGINT NOT NULL DEFAULT 0,
    last_login_at           TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

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
    secret_hash_previous        TEXT,
    secret_previous_expires_at  TIMESTAMPTZ,
    disabled_at                 TIMESTAMPTZ,
    created_by_user_id          UUID REFERENCES users(id) ON DELETE SET NULL,

    CONSTRAINT confidential_requires_secret CHECK (
        (client_type = 'public' AND secret_hash IS NULL) OR
        (client_type = 'confidential' AND secret_hash IS NOT NULL)
    ),
    CONSTRAINT secret_previous_consistency CHECK (
        (secret_hash_previous IS NULL AND secret_previous_expires_at IS NULL) OR
        (secret_hash_previous IS NOT NULL AND secret_previous_expires_at IS NOT NULL)
    )
);

CREATE TABLE scopes (
    name         TEXT PRIMARY KEY,
    description  TEXT NOT NULL,
    is_default   BOOLEAN NOT NULL DEFAULT false,
    is_system    BOOLEAN NOT NULL DEFAULT false
);

INSERT INTO scopes (name, description, is_default, is_system) VALUES
    ('openid',         'OpenID Connect scope',     true,  true),
    ('profile',        'User profile information', true,  true),
    ('email',          'User email address',       false, true),
    ('offline_access', 'Issue refresh tokens',     false, true);

CREATE TABLE authorization_codes (
    code_hash               TEXT PRIMARY KEY,
    client_id               UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id                 UUID NOT NULL REFERENCES users(id),
    redirect_uri            TEXT NOT NULL,
    scopes                  TEXT[] NOT NULL,
    nonce                   TEXT,
    code_challenge          TEXT NOT NULL,
    code_challenge_method   TEXT NOT NULL DEFAULT 'S256'
                                CHECK (code_challenge_method = 'S256'),
    expires_at              TIMESTAMPTZ NOT NULL,
    used                    BOOLEAN NOT NULL DEFAULT false,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    family_id               UUID NOT NULL DEFAULT gen_random_uuid()
);

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

CREATE TABLE audit_logs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type   TEXT NOT NULL,
    actor_id     UUID,
    actor_email  TEXT,
    target_type  TEXT,
    target_id    TEXT,
    client_id    UUID,
    ip_address   INET,
    outcome      TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
    metadata     JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY audit_logs_select ON audit_logs
    FOR SELECT USING (true);

CREATE POLICY audit_logs_insert ON audit_logs
    FOR INSERT WITH CHECK (true);

REVOKE UPDATE, DELETE ON audit_logs FROM PUBLIC;

CREATE TABLE instance_config (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO instance_config (key, value) VALUES
    ('mfa_required',            'true'),
    ('lockout_threshold',       '5'),
    ('lockout_duration_secs',   '900'),
    ('password_min_length',     '12'),
    ('password_require_upper',  'true'),
    ('password_require_digit',  'true'),
    ('access_token_ttl_secs',   '900'),
    ('refresh_token_ttl_secs',  '86400'),
    ('smtp_host',               'null'),
    ('smtp_port',               'null'),
    ('smtp_username',           'null'),
    ('smtp_password',           'null'),
    ('smtp_from',               'null'),
    ('instance_name',           'null'),
    ('setup_complete',          'false');

CREATE TABLE totp_recovery_codes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   BYTEA NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE password_reset_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   BYTEA NOT NULL UNIQUE,
    expires_at   TIMESTAMPTZ NOT NULL,
    used_at      TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip_address   INET
);

CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_locked_until ON users(locked_until) WHERE locked_until IS NOT NULL;
CREATE UNIQUE INDEX users_email_lower_key ON users(LOWER(email));
CREATE INDEX idx_authorization_codes_expires_at ON authorization_codes(expires_at);
CREATE INDEX idx_audit_logs_actor_id ON audit_logs(actor_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_client_id ON audit_logs(client_id);
CREATE INDEX idx_totp_recovery_codes_user_unused
    ON totp_recovery_codes(user_id)
    WHERE used_at IS NULL;
CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);

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

GRANT SELECT, INSERT, UPDATE, DELETE ON users TO schlass_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON clients TO schlass_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON scopes TO schlass_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON authorization_codes TO schlass_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON signing_keys TO schlass_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON instance_config TO schlass_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON totp_recovery_codes TO schlass_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON password_reset_tokens TO schlass_app;
GRANT SELECT, INSERT ON audit_logs TO schlass_app;
REVOKE ALL ON FUNCTION audit_log_pseudonymize_user(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_log_pseudonymize_user(UUID) TO schlass_app;
