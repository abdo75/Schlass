CREATE TABLE users (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                   TEXT NOT NULL UNIQUE,
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
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
