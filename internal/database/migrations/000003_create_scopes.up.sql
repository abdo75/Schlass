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
