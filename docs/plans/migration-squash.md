# Plan — Migration squash (pre-v1 baseline)

**Branch**: `refactor/migration-squash`
**Base**: `main` (`e9c40f7`)
**Implementer**: Codex
**Reviewer**: Claude

## Goal

Collapse the 20 numbered migrations in `internal/database/migrations/` into a single `000001_baseline.{up,down}.sql` pair. Pre-v1, no production databases upgrade-in-place, so we lose intermediate history on purpose.

## Why

Twenty migrations accumulated during pre-v1 development. Several are DDL reversals of earlier ones (`000015` drops `refresh_tokens` created in `000005`; `000011` drops an FK created in `000007`; `000017` rewrites constraints from `000004`; `000012` rewrites the `users.email` uniqueness from `000001`). A new contributor reading the migration history has to mentally replay twenty steps to know what the schema actually looks like today.

A single baseline makes the current shape inspectable at a glance and speeds up local-DB bootstrap. No functional change — the final schema is identical.

## Non-goals

- No schema change. The baseline must be semantically equivalent to applying all 20 migrations in order. Any deliberate change belongs in a new `000002_*.sql` migration, not in this squash.
- No changes to `internal/database/migrate.go`. The `//go:embed migrations/*.sql` glob already picks up whatever is present.
- No CLAUDE.md, architecture.md, or README edits in this PR. Claude will touch `docs/architecture.md` on review if needed.

## Scope

**Added (2 files):**
- `internal/database/migrations/000001_baseline.up.sql`
- `internal/database/migrations/000001_baseline.down.sql`

**Deleted (40 files):**
- `internal/database/migrations/000001_create_users.{up,down}.sql`
- `internal/database/migrations/000002_create_clients.{up,down}.sql`
- `internal/database/migrations/000003_create_scopes.{up,down}.sql`
- `internal/database/migrations/000004_create_authorization_codes.{up,down}.sql`
- `internal/database/migrations/000005_create_refresh_tokens.{up,down}.sql`
- `internal/database/migrations/000006_create_signing_keys.{up,down}.sql`
- `internal/database/migrations/000007_create_audit_logs.{up,down}.sql`
- `internal/database/migrations/000008_create_instance_config.{up,down}.sql`
- `internal/database/migrations/000009_create_indexes.{up,down}.sql`
- `internal/database/migrations/000010_grant_app_privileges.{up,down}.sql`
- `internal/database/migrations/000011_drop_audit_actor_fk.{up,down}.sql`
- `internal/database/migrations/000012_normalize_user_emails.{up,down}.sql`
- `internal/database/migrations/000013_create_totp_recovery_codes_and_counter.{up,down}.sql`
- `internal/database/migrations/000014_add_users_last_login_at.{up,down}.sql`
- `internal/database/migrations/000015_drop_refresh_tokens.{up,down}.sql`
- `internal/database/migrations/000016_auth_code_family_id.{up,down}.sql`
- `internal/database/migrations/000017_alter_clients_add_rotation_and_metadata.{up,down}.sql`
- `internal/database/migrations/000018_audit_pseudonymize_fn.{up,down}.sql`
- `internal/database/migrations/000019_password_reset_tokens.{up,down}.sql`
- `internal/database/migrations/000020_force_expire_reset_tokens.{up,down}.sql`

**Modified:** none.

## Final-state inventory — what must end up in `000001_baseline.up.sql`

Apply all DDL as a single migration running under the `schlass_migrations` role (via `database.RunMigrations`). Table + index order matters for FK dependencies; the order below is one safe topological layout.

### 1. Tables

#### `users`

From `000001` plus `000013` (`last_used_totp_counter`) plus `000014` (`last_login_at`). Do NOT add the original inline `UNIQUE` on `email`; `000012` replaced it with a functional index, and the baseline mirrors the final state. Columns:

- `id UUID PK DEFAULT gen_random_uuid()`
- `email TEXT NOT NULL` — uniqueness enforced below by functional index
- `password_hash TEXT NOT NULL`
- `role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('super_admin','user'))`
- `status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled'))`
- `force_password_change BOOLEAN NOT NULL DEFAULT true`
- `totp_secret_encrypted BYTEA`
- `totp_enrolled_at TIMESTAMPTZ`
- `failed_login_attempts INT NOT NULL DEFAULT 0`
- `locked_until TIMESTAMPTZ`
- `last_used_totp_counter BIGINT NOT NULL DEFAULT 0`
- `last_login_at TIMESTAMPTZ`
- `created_at TIMESTAMPTZ NOT NULL DEFAULT now()`
- `updated_at TIMESTAMPTZ NOT NULL DEFAULT now()`

#### `clients`

From `000002` plus the lifecycle additions from `000017`. Columns:

- original 11 columns from `000002` (including `confidential_requires_secret` CHECK)
- `secret_hash_previous TEXT NULL`
- `secret_previous_expires_at TIMESTAMPTZ NULL`
- `disabled_at TIMESTAMPTZ NULL`
- `created_by_user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL`
- `CONSTRAINT secret_previous_consistency CHECK ((secret_hash_previous IS NULL AND secret_previous_expires_at IS NULL) OR (secret_hash_previous IS NOT NULL AND secret_previous_expires_at IS NOT NULL))`

#### `scopes`

Verbatim from `000003` including the four seed rows (`openid`, `profile`, `email`, `offline_access`).

#### `authorization_codes`

From `000004` plus `000016` (`family_id`) plus `000017` (client FK changed to `ON DELETE CASCADE`). Columns and constraints:

- original 10 columns + `family_id UUID NOT NULL DEFAULT gen_random_uuid()`
- `user_id UUID NOT NULL REFERENCES users(id)`
- `client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE` — the cascade is part of the table definition from the start, not an `ALTER`.

#### `refresh_tokens`

**Do not create.** Migration `000015` dropped it. The baseline skips it entirely.

#### `signing_keys`

Verbatim from `000006`.

#### `audit_logs`

From `000007` minus the FKs on `actor_id` (dropped in `000011`) and `client_id` (dropped in `000017`). Both columns remain as plain UUIDs — historical rows still carry the IDs even after the referenced row is deleted, and join-when-present queries still work. Columns:

- `id`, `event_type`, `actor_id UUID` (no FK), `actor_email TEXT`, `target_type`, `target_id`, `client_id UUID` (no FK), `ip_address INET`, `outcome TEXT CHECK (outcome IN ('success','failure'))`, `metadata JSONB`, `created_at`
- `ENABLE ROW LEVEL SECURITY`
- `CREATE POLICY audit_logs_select ON audit_logs FOR SELECT USING (true);`
- `CREATE POLICY audit_logs_insert ON audit_logs FOR INSERT WITH CHECK (true);`
- `REVOKE UPDATE, DELETE ON audit_logs FROM PUBLIC;`

#### `instance_config`

Verbatim from `000008` including all 15 seed rows.

#### `totp_recovery_codes`

Verbatim from `000013`.

#### `password_reset_tokens`

Verbatim from `000019`. Skip the `UPDATE ... SET used_at = now()` from `000020` — there are no rows to force-expire on a fresh install.

### 2. Indexes (from `000009` + later)

```sql
CREATE INDEX idx_users_status              ON users(status);
CREATE INDEX idx_users_locked_until        ON users(locked_until) WHERE locked_until IS NOT NULL;
CREATE UNIQUE INDEX users_email_lower_key  ON users(LOWER(email));  -- from 000012; replaces 000001's UNIQUE + 000009's idx_users_email
CREATE INDEX idx_authorization_codes_expires_at ON authorization_codes(expires_at);
CREATE INDEX idx_audit_logs_actor_id       ON audit_logs(actor_id);
CREATE INDEX idx_audit_logs_created_at     ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_event_type     ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_client_id      ON audit_logs(client_id);
CREATE INDEX idx_totp_recovery_codes_user_unused ON totp_recovery_codes(user_id) WHERE used_at IS NULL;
CREATE INDEX idx_password_reset_tokens_user_id   ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);
```

Do NOT recreate:
- `idx_users_email` — dropped in `000012`.
- any `idx_refresh_tokens_*` — table no longer exists.

### 3. Functions (from `000018`)

`audit_log_pseudonymize_user(UUID) RETURNS INTEGER` exactly as in `000018`. Running the baseline under the `schlass_migrations` role means the function is owned by `schlass_migrations`, preserving the `SECURITY DEFINER` + EXECUTE-only semantics.

### 4. Grants (from `000010` + `000013` + `000018` + `000019`)

```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON users                  TO schlass_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON clients                TO schlass_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON scopes                 TO schlass_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON authorization_codes    TO schlass_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON signing_keys           TO schlass_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON instance_config        TO schlass_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON totp_recovery_codes    TO schlass_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON password_reset_tokens  TO schlass_app;
GRANT SELECT, INSERT                 ON audit_logs             TO schlass_app;
REVOKE ALL ON FUNCTION audit_log_pseudonymize_user(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_log_pseudonymize_user(UUID) TO schlass_app;
```

Do NOT grant any privilege on `refresh_tokens` — table does not exist.

### 5. Down migration — `000001_baseline.down.sql`

Reverse order. Just drop what was created:

```sql
DROP FUNCTION IF EXISTS audit_log_pseudonymize_user(UUID);
DROP TABLE IF EXISTS password_reset_tokens;
DROP TABLE IF EXISTS totp_recovery_codes;
DROP TABLE IF EXISTS instance_config;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS signing_keys;
DROP TABLE IF EXISTS authorization_codes;
DROP TABLE IF EXISTS scopes;
DROP TABLE IF EXISTS clients;
DROP TABLE IF EXISTS users;
```

`CASCADE` is unnecessary as long as drops are in FK-reverse order. `IF EXISTS` guards against re-runs.

## Verification (Codex must run these)

1. `go vet ./... && golangci-lint run ./...`
2. `make test-unit` — must pass.
3. `make test-integration` — must pass. This is the real gate: 40+ integration tests exercise every column, constraint, grant, and the pseudonymize function. Any divergence from the intended final schema will show up as a SQL error.
4. `go test -tags=integration -run TestMigrationsUpDownUp ./test/integration/... -count=1` — specifically exercises up → down → up on whatever is in `migrations/`. Must pass on the new single-pair.

If integration tests fail:
- First check whether the failure is a missing column, constraint, index, or grant — fix the baseline SQL.
- Do NOT patch the test to work around a real divergence. The tests are the spec.

## Caveats to call out in the PR description

- Any contributor with an existing local dev DB will need to wipe and re-create it: `docker compose down -v && docker compose up --build`. On startup, `golang-migrate` sees `schema_migrations` empty and applies the new baseline cleanly. Running against an existing volume with `schema_migrations.version = 20` will be a no-op (migrate skips already-applied versions, including non-existent ones) — this leaves the old schema in place and is correct behaviour, but users must wipe to get the fresh baseline applied.
- CI runs fresh each time (no persistent volume), so no action needed there.
- No production environments exist yet, so there is no migration path to preserve.

## Commit + PR

Single commit (source + file deletions). Message:

```
refactor(migrations): squash 20 pre-v1 migrations into single baseline

The 20 numbered migrations that accumulated during pre-v1 development
included several reversals (drop refresh_tokens, drop audit FKs, rewrite
email uniqueness). A new contributor reading migrations had to mentally
replay 20 steps to see the current schema. Collapsing them into a
single 000001_baseline.{up,down}.sql makes the shape inspectable at a
glance and speeds up local-DB bootstrap.

Functionally identical: every table, column, constraint, index, grant,
RLS policy, and the audit_log_pseudonymize_user SECURITY DEFINER
function are preserved. The full integration suite is the proof.

Developers with existing local dev DBs must run
`docker compose down -v` to wipe the volume before `docker compose up`;
schema_migrations tracks by version number, so an existing DB will no-op
on the new baseline numbered 000001.
```

PR title matches the commit subject. PR body should reproduce the "Caveats" section verbatim so reviewers see the docker-compose note.

## Handoff checklist

- [ ] Pull `refactor/migration-squash`. Plan file is already committed.
- [ ] Write `000001_baseline.up.sql` per § 1-4 above.
- [ ] Write `000001_baseline.down.sql` per § 5 above.
- [ ] Delete all 40 existing migration files.
- [ ] `make test-unit` green.
- [ ] `make test-integration` green (spin up a fresh `make dev` volume first to be safe).
- [ ] Commit + push + open PR. Title and body per above.
- [ ] Do NOT edit `CLAUDE.md`, `docs/architecture.md`, `docs/plans/migration-squash.md`, or `internal/database/migrate.go`.
