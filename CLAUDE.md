# Schlass — Project Conventions

Self-hosted identity provider for EU-regulated SMEs. Compliance-first (DORA/NIS2), security-first.

## Stack

- **Backend**: Go 1.25+, stdlib `net/http` (no frameworks), `pgx` for PostgreSQL, `go-redis` for Valkey
- **Frontend**: React + TypeScript + Vite + Tailwind v4 + shadcn/ui
- **Database**: PostgreSQL 18, Valkey 9
- **Deployment**: Single binary with embedded SPA via `go:embed`

## Project Structure

```
cmd/schlass/main.go          → entry point, wiring, graceful shutdown
internal/config/              → env loading + config service (instance_config business logic)
internal/crypto/              → AES-256-GCM encryption, Argon2id password hashing
internal/database/            → pgxpool, Querier interface, migrations (embedded SQL)
internal/handler/             → HTTP handlers (setup, health)
internal/middleware/          → security headers, request logging, rate limiting
internal/model/               → validation functions, request types, error types
internal/store/               → data access (config, user, audit) — stateless, accept Querier
internal/valkey/              → Valkey client setup
internal/web/                 → embedded SPA (dist/ is build output, .gitkeep placeholder)
web/                          → React SPA source (Vite + TypeScript + Tailwind + shadcn)
test/integration/             → integration tests with testcontainers (real PG + Valkey)
scripts/                      → init-db.sh (PG role setup)
```

## Key Patterns

### Querier Interface

`internal/database/querier.go` defines a `Querier` interface satisfied by both `pgxpool.Pool` and `pgx.Tx`. All store methods accept `Querier` as their first argument (after `ctx`). This allows the same store methods to work inside and outside transactions without duplication.

```go
// Normal read — pass the pool
configStore.GetBool(ctx, pool, "setup_complete")

// Inside a transaction — pass the tx
tx, _ := pool.Begin(ctx)
userStore.Create(ctx, tx, email, hash, role, false)
configStore.Set(ctx, tx, "setup_complete", true)
tx.Commit(ctx)
```

### Stateless Stores

Stores hold no state (no pool reference). They're method namespaces for related SQL operations. The caller controls the connection.

### Error Types

Use typed errors in `internal/model/errors.go` for distinguishing error categories in handlers:

```go
var validationErr *model.ValidationError
var policyErr *model.PasswordPolicyError
if errors.As(err, &policyErr) { ... }
```

Never match on error message strings.

### Audit Logging

Every state-changing operation must write to `audit_logs` with: event_type, actor_id, actor_email (denormalized), target_type, target_id, ip_address, outcome, metadata. The `actor_email` is stored directly so the audit trail survives user deletion.

## Database

### Two Roles

- `schlass_migrations` — owns tables, runs migrations (DDL). Used only at startup.
- `schlass_app` — runtime role. SELECT/INSERT/UPDATE/DELETE on all tables EXCEPT `audit_logs` (SELECT + INSERT only). RLS enforced.

Migrations auto-run on startup via `database.RunMigrations()`. Located in `internal/database/migrations/` (embedded via `go:embed`).

### Audit Log Tamper Protection

`audit_logs` is append-only, enforced at the database level:
- RLS enabled with only SELECT + INSERT policies
- UPDATE and DELETE revoked from PUBLIC
- `schlass_app` granted only SELECT + INSERT

This is a compliance claim — never weaken it.

## Security Defaults

- MFA required by default (`mfa_required = true`)
- Password policy: min 12 chars, require uppercase + digit
- Argon2id (19 MiB, 2 iterations, 1 parallelism) for password hashing
- AES-256-GCM for encrypting sensitive config (smtp_password, totp_secret)
- Encryption key from `SCHLASS_ENCRYPTION_KEY` env var (32-byte base64)
- Security headers on all responses (HSTS, CSP, X-Frame-Options, etc.)
- Structured JSON logging always (no text mode, dev/prod parity)

## Testing

- **Unit tests**: alongside code in `internal/*/`
- **Integration tests**: `test/integration/` using `testcontainers-go` (real PG + Valkey, no mocks)
- **Run all**: `make test` or `go test ./...`
- **Run unit only**: `make test-unit`
- **Run integration only**: `make test-integration`

Never mock the database. Use testcontainers for anything that touches PG or Valkey.

## Build

- `make build` — build SPA + Go binary (output: `bin/schlass`)
- `make dev` — `docker compose up --build`
- `make dev-frontend` — Vite HMR (proxies `/api` to Go on `:3000`)
- `make build-docker` — Docker image

## Frontend

- Feature-based structure: `web/src/features/<feature>/`
- Shared components in `web/src/components/ui/` (shadcn, copy-and-own)
- API client in `web/src/lib/api.ts` — typed `apiFetch<T>()` wrapper
- i18n via `react-i18next` — translations in `web/src/i18n/locales/{en,fr,de}.json`
- Backend returns error codes, frontend translates to user-facing messages

## Setup for New Clones

```bash
make setup    # installs npm deps + configures git hooks path
```

This sets `core.hooksPath` to `.githooks/` so the pre-commit hook (lint + unit tests) runs automatically.

## Commits

- Conventional commits: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`
- Branch naming: `sprint-N/<feature>` or `pre-sprint-N/<topic>`
- Don't commit `.env`, `node_modules/`, `bin/`, `internal/web/dist/*` (except `.gitkeep`)
- Pre-commit hook runs: Go lint, Go unit tests, frontend ESLint
