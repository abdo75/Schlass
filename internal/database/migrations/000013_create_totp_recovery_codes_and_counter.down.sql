-- internal/database/migrations/000013_create_totp_recovery_codes_and_counter.down.sql
-- Reverses 000013. Drops the table (and any data with it — intentional; a
-- downgrade that needs the recovery codes back has bigger problems) and
-- removes the counter column.

DROP TABLE IF EXISTS totp_recovery_codes;
ALTER TABLE users DROP COLUMN IF EXISTS last_used_totp_counter;
