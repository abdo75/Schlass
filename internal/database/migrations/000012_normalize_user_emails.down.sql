-- internal/database/migrations/000012_normalize_user_emails.down.sql
-- Reverses 000012_normalize_user_emails.up.sql.
--
-- Restores the structural UNIQUE constraint on email and recreates the
-- non-unique idx_users_email. Deliberately does NOT attempt to un-lowercase
-- existing rows — that information is lost once the up migration ran, and
-- any rollback scenario needing mixed-case emails has bigger concerns than
-- this migration.

DROP INDEX IF EXISTS users_email_lower_key;
ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);
CREATE INDEX idx_users_email ON users(email);
