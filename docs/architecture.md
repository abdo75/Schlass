# Schlass — Repository Layout

Where to go when making changes. Read § 1 for the tree, § 2 for import rules, § 3 to drill into a specific package.

## 1. Visual Overview

Tree is grouped by category so the intent of each package is visible at a glance. Within each category, packages are alphabetical.

```
.
├── cmd/schlass/main.go             binary entry + wiring
│
├── internal/
│   │
│   ├── ── Features — own a DB table + serve HTTP endpoints ──
│   ├── auth/                       session-cookie login + MFA + password reset
│   ├── authserver/                 OIDC endpoints
│   ├── clients/                    OIDC client admin + data
│   ├── settings/                   instance-config admin endpoints
│   ├── signingkeys/                signing-key lifecycle + admin + JWKS builder
│   ├── users/                      user admin + data + CurrentUser + RequirePermission
│   │
│   ├── ── Shared domain — stateful cross-feature logic, no HTTP of its own ──
│   ├── audit/                      audit_logs append-only store
│   ├── instanceconfig/             runtime config of Schlass instance
│   ├── oidc/                       OIDC protocol primitives (JWT, PKCE, claims, JWKS types)
│   ├── session/                    Valkey sessions + revoke_before
│   │
│   ├── ── Technical — pure infra + utilities, no Schlass domain knowledge ──
│   ├── apierrors/                  typed errors
│   ├── config/                     env var parsing
│   ├── crypto/                     AES-GCM, Argon2id, TOTP, HIBP, random tokens
│   ├── database/                   pgx pool + Querier + migrations
│   │   └── migrations/             *.up.sql / *.down.sql
│   ├── httputil/                   JSON response helpers
│   ├── mail/                       SMTP client
│   │   └── templates/              email templates
│   ├── middleware/                 HTTP-infra middleware
│   ├── recovery/                   recovery-reset CLI
│   ├── server/                     router + health + setup + dev-seed + sweeper
│   ├── validate/                   email / password / policy validators
│   ├── valkey/                     Valkey pool
│   └── web/                        web UI go:embed handler
│       └── dist/                   web UI build output
│
├── web/                            React frontend (Vite + TS + Tailwind v4 + shadcn/ui) — see § 4
├── test/integration/               testcontainers-go (real PG + Valkey)
├── scripts/                        init-db.sh
├── docs/                           architecture.md, security.md, operator runbooks
│   └── operator/                   shipped runbooks
├── bin/                            (gitignored) `make build` output
│
├── ── tooling / config (repo root) ──
├── README.md                       quickstart
├── LICENSE
├── Makefile                        build / test / lint / dev targets
├── go.mod / go.sum                 Go module
├── Dockerfile                      production image
├── docker-compose.yml              dev stack (PG + Valkey + app + Mailpit)
├── docker-compose.e2e.yml          e2e override
├── .env.example                    SCHLASS_* defaults
├── .golangci.yml                   lint config
├── .githooks/pre-commit            Go lint + unit + ESLint + Vitest
├── .github/workflows/              CI pipelines
├── .gitignore
└── .dockerignore
```

**How to pick a category when adding code:**
- New CRUD endpoint backed by its own DB table → **Feature** package (new or existing).
- Cross-feature domain logic with stateful behaviour but no HTTP surface of its own → **Shared domain** package.
- Pure helper, primitive, or glue with no Schlass-specific knowledge → **Technical** package.

**Flat rule.** No Go subpackages under `internal/`. Only data-only subdirs (`migrations/`, `templates/`, `dist/`). Split long files into more files in the same package — never nest.

## 2. Dependency Direction

```
cmd/schlass/main.go
  → server (router) → features (auth, users, clients, authserver, signingkeys, settings)
    → shared platform (audit, instanceconfig)
    → infrastructure (oidc, session, crypto, middleware, database, mail, valkey)

audit → middleware (for CorrelationID)           middleware has no feature imports
users → audit                                    admin CRUD logs audit
oidc → users (type only)                         users does not import oidc
signingkeys → oidc                               for RSA keygen + envelope wrap
authserver → signingkeys                         discovery reads publishable keys
```

**Rules of thumb when adding code:**
- `middleware/` must never import a feature package — that cycles via `users → audit → middleware → users`.
- `oidc/` must never import `authserver/` or `signingkeys/` — `oidc` is pure protocol layer, the others are domain.
- New features become top-level siblings of `auth/` / `users/` / `clients/`. Don't nest. If a file gets big, add another file in the same package.

## 3. Packages

Each section gives the package's **purpose** (one sentence answering "when do I open this?") and a **files table**. Skim purposes, then drill into the table.

### Features

#### `internal/auth/`

**Purpose:** everything a user does to authenticate themselves — login, logout, MFA, password reset.

| File | Purpose |
|---|---|
| `handler.go` | `POST /api/login`, `POST /api/logout`, `GET /api/me`, `POST /api/change-password`, `POST /api/disable-mfa`. Dummy-Argon2id timing defense + lockout + post-login branching (force change → MFA enrol → MFA challenge → session). |
| `middleware.go` | Session-cookie auth. Reads cookie, fetches user fresh from PG every request, injects via `users.WithCurrentUser`. Orphan/disabled detection writes `session.revoked` best-effort. |
| `optional_middleware.go` | For Bootstrap-style routes that behave differently when authed. Never errors on missing/invalid cookie. |
| `mfa.go` | `MFAHandler` + `NewMFAHandler`. `POST /api/mfa/enrollment/{start,verify,complete}` + `POST /api/mfa/challenge`. TOTP ±1 step + recovery-code constant-time scan + atomic HIncrBy attempts gate. |
| `recovery_code_store.go` | `RecoveryCodeStore`: `Insert/ListUnused/CountUnused/MarkUsed/DeleteAllForUser`. Codes hashed with Argon2id. |
| `password_reset.go` | `PasswordResetHandler`. `POST /api/password-reset/request` (enumeration-safe 200 empty), `POST /api/password-reset/confirm`. Rate-limited. super_admin email reset blocked (NIS2). |
| `password_reset_token_store.go` | HMAC-peppered token table. Pepper = HKDF from `SCHLASS_ENCRYPTION_KEY`, re-derived at startup. |
| `requests.go` + `_test.go` | Login request DTO + validation. |
| `user_dto.go` | Non-sensitive user projection returned by `/api/me`. |
| `helpers.go` | IP extraction + small response helpers. |

#### `internal/users/`

**Purpose:** User data + admin CRUD + the authorization primitives that everyone else gates on.

| File | Purpose |
|---|---|
| `handler.go` | Admin user CRUD (`POST /api/users`, `PATCH`, `DELETE`, `POST reset-password`, `POST reset-mfa`, `DELETE sessions`). `rejectSelfOp` + last-admin lockout helpers. Audit-in-tx. |
| `store.go` | `User` type + CRUD + MFA slot (`SetTOTPEnrolled`, `AdvanceTOTPCounter`, `ClearTOTPEnrollment`) + lockout state. |
| `context.go` | `WithCurrentUser(ctx, *User)` + `CurrentUser(ctx)` — typed context key shared by session + bearer middleware. |
| `permission.go` | `RequirePermission(perm)` middleware + v1 hardcoded `rolePermissions` map (super_admin → all, user → none). |
| `permission_test.go` | RequirePermission + PermissionsForRole unit tests. |

#### `internal/clients/`

**Purpose:** OIDC client data + admin CRUD + redirect-URI / scope / grant validation.

| File | Purpose |
|---|---|
| `handler.go` | Admin client CRUD (8 endpoints). Audit-in-tx per-field PATCH rows. `SELECT ... FOR UPDATE` serializes PATCHes. |
| `store.go` | `Client` type + store + `rotate_secret` with 24h previous-hash overlap. |
| `validate.go` | `ValidateClientName`, `ValidateScopes`, `ValidateGrantTypes`. Allowed scopes = openid / profile / email / offline_access. |
| `redirect_uri.go` | `ValidateRedirectURIInput` — https OR http+loopback per RFC 8252, 2048-byte cap, no fragment, no wildcards. |
| `validate_test.go`, `redirect_uri_test.go` | Validator unit tests. |

#### `internal/authserver/`

**Purpose:** the OIDC HTTP surface — /authorize, /token, /userinfo, /.well-known/*, bearer-token middleware.

| File | Purpose |
|---|---|
| `authorize.go` | `GET /authorize` — PKCE S256 mandatory, `state` required, exact-match redirect_uri. |
| `token.go` | `POST /token` — authorization_code + refresh_token grants. Scope re-intersection against current `client.AllowedScopes`. Every `handleAuthorizationCode` failure branch that commits the tx (client / redirect / PKCE mismatch, user not found, grant or scope removed, user disabled) emits an `oidc.code.<reason>` audit row in the same tx as `ConsumeOnce`. Refresh-grant failures use best-effort audit via `writeBestEffortAudit` (documented exception). |
| `userinfo.go` | `GET /userinfo` — RS256 Bearer JWT, per-scope claims. |
| `discovery.go` | `GET /.well-known/openid-configuration` + `/jwks.json`. Calls `signingkeys.BuildJWKSet`. |
| `bearer_middleware.go` | Access-token verification. Enforces revoke_before cutoff (user + client). |
| `authcode_store.go` | Authorization codes — single-use, replay detection. `token.go` emits `oidc.code.replay_detected` on reuse. |
| `helpers.go` | Token-error writer + client-IP extractor. |
| `token_scope_test.go` | Scope intersection unit tests. |

#### `internal/signingkeys/`

**Purpose:** the signing-key domain — startup bootstrap, scheduled retirement, admin rotation, JWKS construction. Used by main, authserver, and the sweeper — that's why it's top-level, not nested.

| File | Purpose |
|---|---|
| `store.go` | `SigningKey` type + CRUD. Statuses: active / retiring / retired. Imports only `database`. |
| `lifecycle.go` | `Bootstrap(ctx, pool, audit, kek)` — idempotent first-key mint. `RetireSweep(ctx, pool, audit, cutoff)` — moves retiring → retired past TTL. Called from `cmd/schlass/main.go` + admin rotate + nightly sweeper. |
| `handler.go` | `POST /api/admin/signing-keys/rotate` + `POST /.../retire-now`. Post-rotate triggers `RetireSweep`. |
| `jwks.go` | `BuildJWKSet([]*SigningKey) oidc.JWKSet` — DB rows → JWKS. |
| `jwks_test.go` | JWKS builder unit tests. |

#### `internal/settings/`

**Purpose:** `PATCH /api/settings/:domain` admin endpoints that mutate `instance_config`.

| File | Purpose |
|---|---|
| `handler.go` | Four handlers: general, security, tokens, email. Per-field audit rows in same tx; SMTP password metadata = `{changed: true}` only. |
| `validate.go` | SMTP host / port / credentials / from / CRLF-injection defense. |
| `validate_test.go`, `validate_crlf_test.go` | Validator unit tests. |

### Shared domain

#### `internal/audit/`

**Purpose:** the single place that inserts rows into `audit_logs`. Append-only at the DB level; GDPR pseudonymization is the only sanctioned mutation.

| File | Purpose |
|---|---|
| `store.go` | `*audit.Store.Log(ctx, q, Entry)` inserts one row. Merges correlation_id from ctx via `middleware.CorrelationID`. `PseudonymizeUser(ctx, q, userID)` — GDPR Art. 17. |
| `logger.go` | `Logger` (narrow) + `PseudonymizingLogger` (wide) interfaces. `*Store` satisfies both. |

#### `internal/instanceconfig/`

**Purpose:** typed getters + cache over the `instance_config` key-value table. Used anywhere that reads a runtime-configurable value (SMTP, password policy, etc.).

| File | Purpose |
|---|---|
| `store.go` | Raw `instance_config` key-value CRUD. `GetBool` / `GetInt` / `GetString` typed getters. |
| `service.go` | Cache layer in front of the store. |

#### `internal/oidc/`

**Purpose:** pure OIDC protocol primitives — JWT sign/verify, PKCE, claims structs, discovery metadata, refresh-token rotation. HTTP-free so it unit-tests without a server.

| File | Purpose |
|---|---|
| `keys.go` | RSA-2048 keygen + AES-GCM envelope wrap/unwrap (AAD-bound). |
| `jwt.go` | `SignAccessToken`, `SignIDToken`, `ParseJWT` — RS256 only. Rejects `alg=none` + alg-confusion. |
| `claims.go` | `BuildAccessClaims`, `BuildIDClaims`, `BuildUserInfoClaims` + `Scopes`. |
| `jwks.go` | `JWK`, `JWKSet` types + `PublicPEMToJWK(kid, pem) JWK`. |
| `pkce.go` | `VerifyPKCE` — S256 only. |
| `refresh_store.go` | Refresh-token family + rotation + replay detection. |
| `returnto.go` | `SanitizeReturnTo` — scheme+host match `SCHLASS_PUBLIC_URL`, path must equal `/authorize`. |
| `discovery.go` | `BuildDiscoveryMetadata(publicURL)`. |
| `errors.go` | `AuthorizeError` — carries RenderLocally flag for /authorize fail modes. |
| `correlation.go` | Helper for propagating correlation into OIDC-layer logs. |
| `*_test.go` | Protocol primitive tests. |

#### `internal/session/`

**Purpose:** Valkey-backed opaque-token sessions + revoke_before cutoffs + session-cookie helpers.

| File | Purpose |
|---|---|
| `store.go` | Valkey session CRUD. 24h sliding TTL. |
| `revokebefore.go` | `RevokeBeforeSetNow(userID)` / `RevokeBeforeGet` + client variants. 30d TTL in Valkey. |
| `cookie.go` | `SetCookie(w, name, value, maxAge, publicURL)` — Secure flag iff publicURL is https. `IsSecureURL`. |

### Technical

#### `internal/server/`

**Purpose:** router + orchestration glue — one entry point that wires all the feature handlers together and runs startup-only jobs (setup wizard, dev-seed, sweeper).

| File | Purpose |
|---|---|
| `router.go` | `BuildRouter(RouterDeps) http.Handler` — canonical route table used by main + testutil. `RouterDeps.AuditStore` typed as `audit.PseudonymizingLogger` so tests inject fakes. |
| `health.go` | `GET /api/health`. |
| `setup.go`, `setup_request.go` | First-run wizard (creates super_admin + marks `setup_complete`). |
| `setup_request_test.go` | Request DTO unit tests. |
| `bootstrap.go` | `SeedDevClient` — upserts `dev-test-client` when `SCHLASS_DEV=1` + http scheme. |
| `sweeper.go` | `StartSweeper` — nightly ticker bound to main ctx. Deletes expired reset tokens + auth codes in one tx. `RunSweepOnce` exported for tests. |

#### `internal/middleware/`

**Purpose:** HTTP-infra middleware shared by every route — security headers, request logging, rate limiting. Must not import feature packages.

| File | Purpose |
|---|---|
| `security_headers.go` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy. |
| `logging.go` | Structured JSON access log. Writes correlation ID to ctx. |
| `correlation.go` | Typed correlation-ID context key + `WithCorrelationID` / `CorrelationID` helpers. |
| `ratelimit.go` | Valkey-backed per-key sliding window. `NewRateLimiter(client, prefix, limit, window)`. |
| `*_test.go` | Security header contract, log redaction, fail-closed rate-limit tests. |

#### `internal/crypto/`

**Purpose:** one file per cryptographic primitive.

Files: `password.go` (Argon2id + dummy hash + `GenerateTemporaryPassword`), `totp.go`, `recovery_codes.go`, `hibp.go`, `encryption.go` (AES-GCM envelope), `random_token.go`, `token_hmac.go` — plus `_test.go` for each.

#### `internal/database/`

**Purpose:** pgx pool, the `Querier` interface that lets stores work in + out of tx, and embedded SQL migrations.

| File | Purpose |
|---|---|
| `postgres.go` | pgx pool construction + ping. |
| `querier.go` | `Querier` interface satisfied by `*pgxpool.Pool` + `pgx.Tx`. |
| `migrate.go` | `RunMigrations(pool)` — walks embedded SQL files. |
| `migrations/` | Numbered `.up.sql`/`.down.sql` files. |

#### `internal/recovery/`

**Purpose:** the `schlass recovery-reset` CLI — operator last-resort when no super_admin exists.

| File | Purpose |
|---|---|
| `reset.go` | `Run([]string)` CLI entry + `Execute` testable core. Mints 1h single-use token, writes `password_reset.recovery_issued` with `actor_email="system:recovery"`. Gated by `SCHLASS_RECOVERY_MODE=1`. |

#### `internal/apierrors/`

**Purpose:** typed error values handlers unwrap via `errors.As` — never match on `Error()` strings.

| File | Purpose |
|---|---|
| `errors.go` | `ValidationError`, `PasswordPolicyError`. |

#### `internal/httputil/`

**Purpose:** universal JSON response helpers used by every HTTP handler.

| File | Purpose |
|---|---|
| `response.go` | `WriteJSON(w, status, data)`, `WriteError(w, status, code, message)`. |

#### `internal/validate/`

**Purpose:** pure input validators with no HTTP/IO coupling.

| File | Purpose |
|---|---|
| `email.go` | RFC 5322 lite + length + lowercase normalization. |
| `password.go` | Min 12 chars, require uppercase + digit (configurable via instance_config). |
| `validate_test.go` | Unit tests. |

#### `internal/mail/` / `internal/valkey/` / `internal/web/` / `internal/config/`

| Package | Purpose |
|---|---|
| `mail/` | SMTP client (`mail.go`) + `templates/` HTML+text message templates. |
| `valkey/` | Valkey pool + ping + shared client. |
| `web/` | Web UI handler serving `web/dist/` via `go:embed`. |
| `config/` | `env.go` `Load()` — parse + validate all `SCHLASS_*` env vars. |

## 4. Frontend (web/)

Same 3-bucket mental model as the backend: **features** (one folder per user-facing flow), **shared app UI** (layouts/guards/modals/badges used across features), **design primitives** (shadcn + custom visual building blocks, no domain knowledge).

### Tree

```
web/
├── src/
│   ├── main.tsx                    React root; mounts <App /> into #root
│   ├── App.tsx                     router declaration, provider composition
│   ├── index.css                   Tailwind v4 imports + oklch design tokens
│   │
│   ├── features/                   one folder per user-facing flow
│   │   ├── account/                user self-account page
│   │   ├── auth/                   login, logout, me, change-password, forgot + reset, authorize-error, AuthContext, permissions, usePermission
│   │   ├── clients/                admin OIDC client CRUD + signing-key rotate/retire page
│   │   ├── mfa/                    TOTP enrollment wizard + challenge + recovery codes
│   │   ├── settings/               /admin/settings tabs (general / security / tokens / email)
│   │   ├── setup/                  first-run wizard
│   │   └── users/                  admin user CRUD
│   │
│   ├── components/                 shared app UI reused across features
│   │   ├── AuthLayout.tsx          wraps public routes (login / setup / etc.)
│   │   ├── AdminLayout.tsx         wraps admin routes (nav + sidebar + chrome)
│   │   ├── AuthGuard.tsx           unauthed → /login; force-change → /change-password
│   │   ├── AdminGuard.tsx          non-super_admin → /account
│   │   ├── RoleBadge.tsx           super_admin / user badge
│   │   ├── StatusBadge.tsx         active / disabled badge
│   │   ├── ClientSecretModal.tsx   reveal-once secret modal
│   │   ├── TempPasswordModal.tsx   reveal-once temp-password modal
│   │   ├── ConfirmDialog.tsx       destructive-action confirmation + type-to-confirm
│   │   ├── Pagination.tsx          table pagination
│   │   ├── PageSkeleton.tsx        skeleton loader
│   │   ├── UserMenuPopover.tsx     admin layout user menu
│   │   ├── LanguageSwitcher.tsx    en / fr / de switch
│   │   ├── ThemeToggle.tsx         light / dark / system cycle
│   │   └── ui/                     design primitives — see § 4 tables
│   │
│   ├── lib/
│   │   ├── api.ts                  typed apiFetch<T>(); credentials: include; 401 → /login
│   │   └── utils.ts                cn() Tailwind class merger (clsx + tailwind-merge)
│   │
│   ├── i18n/
│   │   └── locales/                en.json / fr.json / de.json
│   │
│   └── test/                       Vitest setup — global mocks + JSDOM env
│
├── e2e/                            Playwright tests against docker-compose.e2e.yml
├── public/                         static assets (favicon, robots, etc.)
├── index.html                      Vite entry HTML
├── package.json                    npm deps + scripts
├── vite.config.ts                  Vite + Tailwind + path alias (@/)
├── vitest.config.ts                Vitest config
├── eslint.config.ts                ESLint config
├── tsconfig.json                   TypeScript compiler settings
└── playwright.config.ts            Playwright E2E config
```

### How to pick where code goes

- New admin route or user flow → new folder under `features/`
- Component reused across features (layouts, guards, modals, domain badges) → `components/`
- Purely visual primitive reused anywhere → `components/ui/` (shadcn kebab-case if generated, PascalCase if custom)
- Typed HTTP wrapper for a backend endpoint → feature's own `api.ts`

### Feature folders — extra detail

Each feature folder follows the same convention: `<PageName>.tsx` for routed pages, `api.ts` for typed backend wrappers, feature-local helpers (constants, hooks), `__tests__/` for Vitest + RTL tests.

| Folder | Route(s) + key files |
|---|---|
| `account/` | `/account` — `UserAccountPage` (view own profile, disable MFA). |
| `auth/` | `/login`, `/change-password`, `/forgot-password`, `/reset-password/:token`, `/authorize-error`. `AuthContext` (session provider), `permissions.ts` (PERMISSIONS constants), `usePermission` hook, `api.ts` (login/logout/me/change-password + password-reset endpoints). |
| `clients/` | `/admin/clients`, `/admin/clients/new`, `/admin/clients/:id`, `/admin/signing-keys`. |
| `mfa/` | `/setup-mfa` (`TotpEnrollmentWizard` with 3 steps), `/mfa-challenge` (`TotpChallengePage`). |
| `settings/` | `/admin/settings` with 4 tabs + `FloatingSaveBar` dirty-state UX. |
| `setup/` | `/setup` first-run wizard — creates super_admin and flips `setup_complete`. |
| `users/` | `/admin/users`, `/admin/users/new`, `/admin/users/:id`. |

### Design primitives (`components/ui/`)

Two naming conventions encode origin:

| Files | Source |
|---|---|
| `alert-dialog.tsx`, `button.tsx`, `card.tsx`, `dropdown-menu.tsx`, `input.tsx`, `label.tsx`, `sonner.tsx`, `table.tsx` | shadcn (kebab-case). Install new ones with `npx shadcn@latest add <name>`. |
| `CopyButton.tsx`, `NumberInput.tsx` | Custom primitives (PascalCase). Not from shadcn; edit freely. |

### i18n

`i18n/locales/{en,fr,de}.json` hold every user-facing string. Detection: browser → `localStorage["schlass-language"]`. Backend returns error codes; frontend translates via `t(\`errors.${code}\`)`.

### E2E

`web/e2e/` holds `@playwright/test` tests that run against the dockerized full-stack (`docker-compose.e2e.yml`). Only tier that exercises the shipping artifact in a real browser — integration tests via `httptest.NewRecorder` do not evaluate CSP, SameSite, or frontend bootstrap.

## 5. Cross-Cutting Invariants

These are the project-wide rules every new handler, store, and test must respect:

- **Querier**: `ctx, q, ...` first-two-args convention; same method works in + out of tx.
- **Audit-in-tx**: every state-changing op writes audit inside the same `pgx.Tx` as the mutation.
- **Config audit**: `PATCH /api/settings/:domain` emits one audit row per changed field.
- **Session model**: opaque-token cookie, `SameSite=Lax`, 24h sliding TTL, revoke_before cutoffs.
- **Enumeration defense**: dummy Argon2id hash on unknown-user login + password-reset request.
- **Token HMAC pepper**: HKDF from `SCHLASS_ENCRYPTION_KEY`, re-derived at startup.
- **Signing-key rotation**: active → retiring → retired. JWKS publishes active + retiring.
- **Refresh rotation**: rotate-on-every-use, family replay detected → revoke family.
- **return_to whitelist**: three carriers (MFA Valkey, `Session.PendingReturnTo`, JSON `redirect_to`) all revalidate via `oidc.SanitizeReturnTo`.
- **Email canonicalization**: lowercase at handler + DB `LOWER()` unique index.
- **Temporary passwords**: server-generated 16-char, returned once, never stored/logged/audited.
- **Permission check**: handlers gate with `users.RequirePermission("<resource>.<action>")`. Handlers don't read `user.Role` for authorization.
