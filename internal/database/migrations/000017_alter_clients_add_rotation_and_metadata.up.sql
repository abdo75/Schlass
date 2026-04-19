-- 000017_alter_clients_add_rotation_and_metadata.up.sql
--
-- Secret rotation overlap window (2026 standard: new + previous both valid
-- for 24h). disabled_at and created_by_user_id support client lifecycle mgmt.
--
-- audit_logs.client_id FK is dropped so a client hard-delete does not block
-- on historical audit rows. Precedent: migration 000011 for actor_id.
--
-- authorization_codes gets ON DELETE CASCADE so a client delete atomically
-- cleans up any pending codes (they TTL within minutes anyway).

-- Secret rotation overlap window + lifecycle columns.
ALTER TABLE clients
    ADD COLUMN secret_hash_previous        TEXT NULL,
    ADD COLUMN secret_previous_expires_at  TIMESTAMPTZ NULL,
    ADD COLUMN disabled_at                 TIMESTAMPTZ NULL,
    ADD COLUMN created_by_user_id          UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    ADD CONSTRAINT secret_previous_consistency CHECK (
        (secret_hash_previous IS NULL AND secret_previous_expires_at IS NULL) OR
        (secret_hash_previous IS NOT NULL AND secret_previous_expires_at IS NOT NULL)
    );

-- Hard-delete support: drop audit_logs.client_id FK so a client delete does
-- not block on historical audit rows. Keep the column. Precedent: migration
-- 000011 did this for actor_id.
ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_client_id_fkey;

-- Cascade pending authorization codes on client delete. Codes TTL within
-- minutes; cascade keeps the delete atomic.
ALTER TABLE authorization_codes
    DROP CONSTRAINT IF EXISTS authorization_codes_client_id_fkey,
    ADD  CONSTRAINT authorization_codes_client_id_fkey
        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE;
