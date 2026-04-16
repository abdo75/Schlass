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

### Sessions & Auth (Sprint 2+)

Admin UI uses a **first-party opaque-token session** — not OIDC. Login issues a 32-byte random token (base64url, `crypto/rand`), stored in Valkey as `session:<token>` → `{"user_id":"..."}` with a 24h sliding TTL. Cookie attributes: `HttpOnly; SameSite=Strict; Path=/; MaxAge=86400`; the `Secure` flag is toggled by the `SCHLASS_PUBLIC_URL` scheme at handler construction time (true iff `https://`).

The auth middleware (`internal/middleware/auth.go`) reads the cookie, fetches the user fresh from Postgres on every request (no denormalization of email/role/status into the session), and injects via `middleware.CurrentUser(ctx)`. Disabled users are revoked in-middleware with a `session.revoked` audit row.

**Audit-in-tx rule.** Login success/failure and logout write their audit rows *inside the same PG transaction* as the state change (counter increment/reset, session destruction). The tx commits before any Valkey side-effect (`session.Create` for login, `session.Delete` for logout), so "state change with no audit" is impossible by construction; the reverse ("audit with no Valkey effect") produces only a retry, not a compliance gap. See `internal/handler/setup.go:100-147` and `internal/handler/auth.go PostLogin/PostLogout` for the reference implementations.

**Documented exception — middleware session revocation is best-effort.** When the auth middleware detects an orphan session (user row gone) or a disabled user, it writes a `session.revoked` audit row via `_ = auditStore.Log(...)` (return value ignored, ERROR-level `slog` on failure) and unconditionally deletes the Valkey session. This is deliberately different from the audit-in-tx rule for two reasons: (a) the load-bearing compliance event is the original *user-disable* action at its source (Sprint 4+), not the subsequent cleanup in the middleware; (b) making middleware revocation audit-in-tx would wedge every authed request on PG errors, trading availability for a duplicate audit row. **Do not "fix" this to audit-in-tx** — it would break the "PG blip must not force-logout active users" property.

**Enumeration defense.** The login handler pre-computes a dummy Argon2id hash in `NewAuthHandler` and runs `crypto.VerifyPassword` against it on the user-not-found path so response timing matches the real password-verify path. Rate limiting is 5 requests per minute per IP on `POST /api/login`. Lockout is account-keyed via `users.failed_login_attempts` + `users.locked_until` with a concurrent-safe `UPDATE ... WHERE (locked_until IS NULL OR locked_until < now()) RETURNING ...` pattern in both `IncrementFailedLogins` and `ResetFailedLogins` (the latter refuses to clear an active lock, preserving the lockout duration against concurrent races).

**Known limitation — enumeration timing parity is imperfect.** The dummy-hash trick equalizes the Argon2id cost between the known-wrong-password and unknown-user paths, but the post-hash pipeline diverges: known-wrong does an extra `IncrementFailedLogins` UPDATE plus a richer audit row, which adds ~4ms on localhost (measured during the Sprint 2 security audit). Network jitter swamps this in practice, but a well-connected attacker with millions of probes could statistically distinguish the two states. This is an accepted trade-off for Sprint 2's single-admin threat model — an attacker already knows an admin exists, so the enumeration surface is moot. Revisit when Sprint 5+ adds multi-user management and the surface widens; the likely fix is to run a no-op UPDATE against a fake user id in the unknown-user path to equalize the full pipeline, not just the crypto step.

**AuditLogger interface.** `internal/handler/auth.go` defines `type AuditLogger interface { Log(ctx, q, entry) error }` (exported) so the router wiring and integration test harness can inject a fake audit store. `*store.AuditStore` satisfies the interface unchanged. `internal/middleware/auth.go` defines a parallel unexported interface of the same shape (middleware cannot import handler without a circular dep).

**Router wiring lives in `internal/server/router.go`** via `BuildRouter(RouterDeps) (http.Handler, error)`. Both `cmd/schlass/main.go` and `test/integration/testutil.go` use this single function — any future route or middleware change lands in one place and both production and tests pick it up.

End-user (third-party client) OIDC sessions are a separate mechanism to be built in Sprint 6+; admin web sessions never interact with them.

### Authorization (Sprint 3+)

`middleware.RequireRole(roles ...string)` is the role-gate, wrapped *after* `middleware.Auth` in the chain so the user is already in context. It returns 403 `FORBIDDEN` when the authenticated user's role is not in the allowed set, and 401 `INVALID_SESSION` if no user is in context (a wiring bug). All `/api/users/*` routes are gated by `RequireRole("super_admin")` in `internal/server/router.go`; the only authed-but-unrestricted exception is `POST /api/change-password`, which is self-service. Handlers must never re-check `user.Role` — the middleware already decided.

Destructive handlers (disable, delete, role-demote PATCH) call `rejectSelfOp` as their first action: it's cheap, fails fast with 400 `CANNOT_OPERATE_ON_SELF`, and avoids any DB work for the obvious cases. Last-admin lockout is enforced with a `SELECT id FROM users WHERE role = 'super_admin' FOR UPDATE` that serializes concurrent destructive operations on the admin set, followed by a post-operation count check inside the same transaction as the correctness backstop. The lock deliberately omits `status = 'active'` so it also serializes against concurrent enable/disable flips — narrowing it would let a parallel re-enable slip past the count check. The shared helpers — `lockSuperAdminsForUpdate`, `remainingActiveSuperAdmins`, `enforceLastAdminLockout`, and `rejectSelfOp` — all live in `internal/handler/users.go`. Sprint 4's client-management routes will reuse the same `RequireRole` wrapper unchanged.

### Temporary Passwords (Sprint 3+)

Admin-created users receive a server-generated 16-character temporary password (`internal/crypto/password.go:GenerateTemporaryPassword`). The alphabet is base58-minus-ambiguous-characters (no `0/O/I/l/1`), yielding ~93 bits of entropy. The plaintext is returned once in the HTTP response body and never stored, logged, or written to audit rows. `force_password_change=true` forces the user to rotate it on first sign-in. Both `POST /api/users` (create) and `POST /api/users/:id/reset-password` (admin reset) use this flow — admins never type passwords.

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
- **E2E tests**: `web/e2e/` using `@playwright/test` against a dockerized stack. Run locally via `make e2e` (which does `docker compose down -v && up --build -d && wait-for-health && playwright test`). CI runs the same via the `e2e` job in `.github/workflows/ci.yml`. This is the only test tier that exercises the actual shipping artifact in a real browser — integration tests go through `httptest.NewRecorder` which does not evaluate CSP, SameSite cookies, or the SPA bootstrap sequence. The disabled-user revocation case is intentionally deferred to Sprint 4 pairing (requires admin user-management endpoints to toggle users without coupling tests to the DB schema).

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
- Frontend tests: Vitest + React Testing Library (`cd web && npm test`)

### Design System

- Primary color: teal (oklch). CSS variables in `web/src/index.css`.
- Dark mode: supported via `.dark` class on `<html>`. `ThemeToggle` component cycles light/dark/system.
- `AuthLayout` component: shared wrapper for auth pages (setup, login, password change). Includes Schlass branding + language switcher.
- shadcn components are copy-and-own in `web/src/components/ui/`. Install new ones with `npx shadcn@latest add <name>`.

### Design System (Sprint 3+)

Typography scale: 24px (auth page titles), 20px (admin card titles), 18px (page titles), 14px (default UI), 13px (secondary metadata), 12px (labels/badges). Height tiers: 32px (controls), 36px (auth submit buttons, row avatars), 24px (badges). All colors from oklch tokens in `web/src/index.css` — `--primary` (teal), `--accent` (light teal), `--destructive` (red), `--warning` (amber, used by temp password reveal only), `--muted`, `--border`. No hex values anywhere in components.

### i18n

- Languages: English (default), French, German
- All user-facing strings use `t()` from `react-i18next`
- Backend error codes map to translated messages via `t(\`errors.\${code}\`)`
- Language detection: browser preference → localStorage (`schlass-language`)
- Add new strings to all 3 locale files: `web/src/i18n/locales/{en,fr,de}.json`

## Setup for New Clones

```bash
make setup    # installs npm deps + configures git hooks path
```

This sets `core.hooksPath` to `.githooks/` so the pre-commit hook (lint + unit tests) runs automatically.

## Commits

- Conventional commits: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`
- Branch naming: `<type>/<slug>` following Conventional Commits types — `feat/`, `fix/`, `docs/`, `chore/`, `refactor/`, `test/`, `ci/`. Slug is 2-4 kebab-case words describing *what* not *how* (e.g. `feat/admin-login`, `fix/ci-lint`, `docs/sessions-auth`). Sprint tracking lives in issue trackers / PR milestones, not branch names.
- Don't commit `.env`, `node_modules/`, `bin/`, `internal/web/dist/*` (except `.gitkeep`)
- Pre-commit hook runs: Go lint, Go unit tests, ESLint, Vitest
