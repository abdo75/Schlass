# Schlass

A self-hosted, open-source identity provider targeted at EU-regulated SMEs.

Built for organisations that need documented, auditable identity and access management to comply with DORA and NIS2 — without the cost and complexity of Okta, Entra ID, or Keycloak.

> ⚠️ **Pre-v1 · not production-ready.** This is a personal portfolio project. It runs end-to-end and is extensively tested, but it has not been security-audited, battle-tested in production, or validated against real compliance audits. **Do not deploy it as your real identity layer.**

## What's in the box

- OIDC / OAuth 2.1 provider — `authorization_code` + `refresh_token` grants, PKCE S256 mandatory, RS256 JWTs, rotating signing keys
- TOTP MFA with single-use recovery codes; admin-reset + self-disable flows
- Admin UIs — users, OIDC clients, signing keys, instance settings
- Append-only audit log enforced at the database level (RLS + GDPR Art. 17 pseudonymization)
- Password reset — SMTP-delivered single-use tokens, HIBP breach-corpus check, super_admin self-reset blocked
- i18n: EN / FR / DE · light + dark theme
- Single self-hosted Go binary; web UI embedded via `go:embed`

Integration example: [docs/operator/oidc-rp-integration.md](docs/operator/oidc-rp-integration.md) walks through wiring Grafana OSS as a relying party.

## Quick Start

```bash
git clone https://github.com/abdo75/Schlass.git
cd Schlass
make setup

cp .env.example .env
# Generate a real encryption key and paste it into .env:
openssl rand -base64 32

make dev
```

Open `http://localhost:3000` — the web UI detects whether setup is complete and routes you to `/setup` (first run) or `/login`.

## Development

```bash
make setup             # Install dependencies + configure git hooks
make dev               # Start all services via docker compose
make dev-frontend      # Vite HMR; proxies /api to the Go backend on :3000

make test              # All Go tests (unit + integration)
make test-unit         # Go unit tests only (fast)
make test-integration  # Go integration tests (testcontainers PG + Valkey, ~60s)
make e2e               # Playwright against a fresh dockerized stack

make lint              # Go + frontend linters
make lint-fix          # Auto-fix where possible
make build             # Build production binary to bin/schlass
```

Frontend-only tests run from `web/`: `cd web && npm test` (Vitest unit) and `cd web && npx playwright test` (E2E, requires the stack running).

## Testing strategy

Four types of tests:

- **Go unit** — pure functions, validators (alongside code in `internal/*/`)
- **Go integration** — HTTP handlers against real PostgreSQL + Valkey via testcontainers-go (`test/integration/`)
- **Vitest frontend** — React components with mocked API (`web/src/**/__tests__/`)
- **Playwright E2E** — real Chromium against a dockerized stack (`web/e2e/`); checks the go binary including CSP, cookies, and frontend bootstrap.

Security design notes: [docs/security.md](docs/security.md).

## Stack

- **Backend:** Go 1.25, stdlib `net/http`, `pgx` for PostgreSQL, `go-redis` for Valkey, `testcontainers-go` for integration tests
- **Frontend:** React 19, TypeScript, Vite, Tailwind CSS v4, shadcn/ui, react-router-dom, react-i18next
- **Data:** PostgreSQL 18 (two roles: `schlass_migrations` for DDL, `schlass_app` for runtime), Valkey 9
- **Deployment:** Single Go binary with the web UI embedded via `go:embed`
