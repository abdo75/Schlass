-- 000017_alter_clients_add_rotation_and_metadata.down.sql

ALTER TABLE authorization_codes
    DROP CONSTRAINT IF EXISTS authorization_codes_client_id_fkey,
    ADD  CONSTRAINT authorization_codes_client_id_fkey
        FOREIGN KEY (client_id) REFERENCES clients(id);

ALTER TABLE audit_logs
    ADD CONSTRAINT audit_logs_client_id_fkey
        FOREIGN KEY (client_id) REFERENCES clients(id);

ALTER TABLE clients
    DROP CONSTRAINT IF EXISTS secret_previous_consistency,
    DROP COLUMN IF EXISTS created_by_user_id,
    DROP COLUMN IF EXISTS disabled_at,
    DROP COLUMN IF EXISTS secret_previous_expires_at,
    DROP COLUMN IF EXISTS secret_hash_previous;
