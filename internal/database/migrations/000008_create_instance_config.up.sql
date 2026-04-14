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
