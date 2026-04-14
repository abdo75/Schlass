# Schlass

A self-hosted, open-source identity provider for EU-regulated SMEs.

Built for organisations that need documented, auditable identity and access management to comply with DORA and NIS2 — without the cost and complexity of Okta, Entra ID, or Keycloak.

## Status

Early development. The project is building toward OIDC/OAuth 2.1 support in a series of vertical slices.

**Working today:**
- First-run setup wizard (creates the first Super Admin)
- Super Admin login with session cookies (Valkey-backed opaque tokens, 24h sliding TTL)
- Account lockout after 5 failed login attempts (configurable, 15-minute default)
- Per-IP rate limiting on authentication endpoints
- Origin-header check (login CSRF defence)
- Append-only audit log enforced at the database level via RLS
- Three locales: English, French, German
- Light, dark, and system theme modes
- Single-binary deployment with embedded SPA

**Not yet built (planned):** MFA/TOTP, OIDC `/authorize` + `/token` endpoints, JWKS, client management UI, user management UI, SMTP-backed password reset.

## Quick Start

```bash
git clone https://github.com/abdo75/Schlass.git
cd Schlass
make setup

cp .env.example .env
# Generate a real encryption key and replace SCHLASS_ENCRYPTION_KEY in .env:
openssl rand -base64 32

make dev
```

Open `http://localhost:3000` — the SPA detects whether setup is complete and routes you to `/setup` (first run) or `/login`.

## Development

```bash
make setup             # Install dependencies + configure git hooks
make dev               # Start all services via docker compose
make dev-frontend      # Vite HMR; proxies /api to the Go backend on :3000

make test              # All Go tests (unit + integration)
make test-unit         # Go unit tests only (fast)
make test-integration  # Go integration tests (testcontainers PG + Valkey, ~100s)
make e2e               # Playwright against a fresh dockerized stack

make lint              # Go + frontend linters
make lint-fix          # Auto-fix lint issues where possible
make build             # Build production binary to bin/schlass
```

Frontend-only tests run from `web/`: `cd web && npm test` (Vitest unit) and `cd web && npx playwright test` (E2E, requires the stack running).

## Testing strategy

Four test tiers, each proving something the others can't:

- **Go unit** — pure functions, validation logic (alongside code in `internal/*/`)
- **Go integration** — HTTP handlers against real PostgreSQL + Valkey via testcontainers-go (`test/integration/`)
- **Vitest frontend** — React components with mocked API (`web/src/**/__tests__/`)
- **Playwright E2E** — real Chromium against a dockerized stack (`web/e2e/`); the only tier that exercises the actual shipping artifact including CSP, cookies, and the SPA bootstrap sequence

See `CLAUDE.md` for project conventions, transaction patterns, and the Sessions & Auth architecture. See `docs/v1-scope.md` for the full V1 product scope.

## Stack

- **Backend:** Go 1.25, stdlib `net/http`, `pgx` for PostgreSQL, `go-redis` for Valkey, `testcontainers-go` for integration tests
- **Frontend:** React 19, TypeScript, Vite, Tailwind CSS v4, shadcn/ui, react-router-dom, react-i18next
- **Data:** PostgreSQL 18 (two roles: `schlass_migrations` for DDL, `schlass_app` for runtime), Valkey 9
- **Deployment:** Single Go binary with the SPA embedded via `go:embed`

## License

[AGPL-3.0](LICENSE)
