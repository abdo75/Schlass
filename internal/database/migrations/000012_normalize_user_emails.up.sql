-- internal/database/migrations/000012_normalize_user_emails.up.sql
-- Canonicalizes all users.email rows to lowercase and enforces the
-- canonicalization at the database level via a functional unique index.
--
-- Before this migration: the handler layer lowercases on write (Task 10),
-- but the UNIQUE constraint is on the raw email column. A direct SQL insert
-- (psql, a SQL-loader handler, a migration bug) could insert mixed-case rows
-- that collide semantically but not structurally.
--
-- After: existing rows are lowercased; the structural UNIQUE constraint is
-- replaced by a functional unique index on LOWER(email) so any future
-- inserter that forgets to lowercase still fails loudly at COMMIT time
-- instead of creating a phantom duplicate.
--
-- Collision handling during the UPDATE: if two pre-migration rows differ
-- only in case (e.g. 'Alice@x' and 'alice@x'), the UPDATE would violate the
-- old UNIQUE constraint. We surface a clear error rather than silently
-- dropping one of them; the DO block below catches it.
-- In practice this is rare — the handler path has always validated emails —
-- but the DO block below catches it.

DO $$
DECLARE
  collision_count integer;
BEGIN
  SELECT COUNT(*) INTO collision_count
    FROM (
      SELECT LOWER(email) AS lower_email, COUNT(*) AS c
        FROM users
        GROUP BY LOWER(email)
        HAVING COUNT(*) > 1
    ) dupes;
  IF collision_count > 0 THEN
    RAISE EXCEPTION 'migration 000012: % case-variant duplicate emails detected; resolve manually before rerunning', collision_count;
  END IF;
END $$;

-- Lowercase every row (idempotent — rerunning is a no-op after the first run).
UPDATE users SET email = LOWER(email) WHERE email <> LOWER(email);

-- Drop the structural UNIQUE and replace with a functional unique index.
ALTER TABLE users DROP CONSTRAINT users_email_key;
CREATE UNIQUE INDEX users_email_lower_key ON users(LOWER(email));

-- The existing non-unique idx_users_email (migration 000009) covered
-- case-sensitive lookups; the new functional index supersedes it for the
-- canonical-lookup path. Drop the old one so there are no redundant indexes.
DROP INDEX IF EXISTS idx_users_email;
