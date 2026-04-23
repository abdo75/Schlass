# Schlass — Project Conventions

Self-hosted identity provider for EU-regulated SMEs. Compliance-first (DORA/NIS2), security-first.

## Stack

- **Backend**: Go 1.25+, stdlib `net/http`, `pgx`, `go-redis` (Valkey)
- **Frontend**: React + TypeScript + Vite + Tailwind v4 + shadcn/ui
- **DB**: PostgreSQL 18, Valkey 9
- **Deploy**: single binary, embedded SPA via `go:embed`

## Project Structure

Flat vertical-slice layout: one folder per feature holds type + store + handler + feature-local validators + feature-local middleware. Each feature package owns the DB tables it mutates. No Go subpackages — files over folders. Data-only subdirs (migrations, templates, dist) are fine.

```
cmd/schlass/main.go     entry, wiring, graceful shutdown

internal/
  ── features ──
  auth/                 login, logout, me, change-password, session mw, MFA, password reset, optional mw
  users/                User + user_store + admin CRUD + RequirePermission + CurrentUser
  clients/              Client + client_store + admin CRUD + redirect_uri + scope validators
  authserver/           OIDC /authorize /token /userinfo + auth_code_store + bearer mw
  signingkeys/          SigningKey + store + Bootstrap/RetireSweep + admin rotate/retire + JWKS builder
  settings/             instance-config PATCH + SMTP validators

  ── shared platform ──
  audit/                Logger + PseudonymizingLogger + Store
  instanceconfig/       config service + store (cross-cutting)

  ── shared utilities ──
  apierrors/            ValidationError, PasswordPolicyError
  httputil/             WriteJSON, WriteError
  validate/             Email, Password, PasswordPolicy

  ── infrastructure ──
  server/               BuildRouter + /api/health + setup wizard + dev seed + nightly sweeper
  middleware/           security_headers, logging (correlation ID), ratelimit (HTTP-infra only — no domain imports)
  oidc/                 JWT sign/verify, PKCE, claims, discovery, refresh_store, SanitizeReturnTo, RSA keygen, envelope wrap
  session/              session Valkey store + revoke_before (user + client) + cookie helpers
  crypto/               AES-256-GCM, Argon2id, TOTP, recovery codes, HIBP, RandomToken
  database/             pgxpool, Querier, embedded migrations
  mail/ valkey/ web/ config/ recovery/

web/                    React SPA source
test/integration/       testcontainers (real PG + Valkey)
scripts/                init-db.sh
```

**Naming rule.** One package per feature, plural noun (`users`, `clients`, `signingkeys`). Feature package owns its type + store + handler + any feature-local helpers. `users.User`, `users.Store`, `users.Handler`, `users.RequirePermission`, `users.CurrentUser` all live in the same package. No Go subpackages — if a file gets big, split it into more files in the same package; don't nest.

**Dependency direction.** Features may import `audit`, `oidc`, `session`, `crypto`, `httputil`, `validate`, `apierrors`, `middleware`, `database`, `instanceconfig`. `middleware` imports only utilities — never feature packages (would cycle via `users → audit → middleware`). `oidc` is pure protocol primitives + imports only `crypto` + `users` (type). Signing-key lifecycle lives in `signingkeys/`, not `oidc` or `authserver`.

## Key Patterns

### Querier Interface

`internal/database/querier.go` defines `Querier` satisfied by `pgxpool.Pool` + `pgx.Tx`. Store methods take `Querier` as first arg after `ctx` — same method works in + out of tx.

```go
configStore.GetBool(ctx, pool, "setup_complete")           // pool
tx, _ := pool.Begin(ctx)                                   // tx
userStore.Create(ctx, tx, email, hash, role, false)
configStore.Set(ctx, tx, "setup_complete", true)
tx.Commit(ctx)
```

### Stateless Stores

No state, no pool ref. Method namespaces. Caller owns connection.

### Error Types

Typed errors in `internal/apierrors/errors.go`. Use `errors.As` — never match on message strings.

```go
var policyErr *apierrors.PasswordPolicyError
if errors.As(err, &policyErr) { ... }
```

### Audit-in-tx rule

Every state-changing op writes to `audit_logs` (event_type, actor_id, actor_email denormalized, target_type, target_id, ip_address, outcome, metadata) **inside the same PG tx as the state change**. Tx commits before any Valkey side-effect. `actor_email` stored directly so trail survives user deletion.

**Documented exceptions (best-effort audit, do NOT "fix" to audit-in-tx):**
- **Middleware session revocation** (`internal/middleware/auth.go`): orphan/disabled user detection writes `session.revoked` via `_ = auditStore.Log(...)`. Why: load-bearing compliance event is the user-disable action itself; audit-in-tx here would force-logout every authed user on PG blip.
- **MFA challenge failed** (`mfa.challenge_failed`): written in separate short-lived tx. Why: brute-force guard is the atomic Valkey `HIncrBy ... -1` decrement (structural), audit row is forensic.
- **revoke_before enforcement** (`user.revoke_before_enforced`): best-effort on reject path.

### Config mutation audit

Every handler writing `instance_config` audits `config.<key>.changed` in same PG tx as the write. No best-effort exception — config changes = most-scrutinized audit item. Reference impl: `internal/settings/handler.go` — four `PATCH /api/settings/:domain` endpoints (General, Security, Tokens, Email) emit one row per changed field. `smtp_password` metadata is `{"changed": true}` only — never leak plaintext/ciphertext. Pattern for new fields: snapshot pre-values → build change list → open tx → loop write+audit → commit.

### Sessions & Auth

Admin UI uses first-party opaque-token session — NOT OIDC. Login issues 32-byte `crypto/rand` token (base64url), stored in Valkey `session:<token>` with 24h sliding TTL. Cookie: `HttpOnly; SameSite=Lax; Path=/; MaxAge=86400`. `Secure` flag = true iff `SCHLASS_PUBLIC_URL` is `https://`.

**`SameSite=Lax` (not Strict) is deliberate** — `/authorize` is the entry for cross-site top-level redirects from OIDC RPs; Strict would hide the cookie + force duplicate login. Lax still blocks cross-site sub-resource + cross-site POST/PATCH/DELETE (CSRF model). MFA cookies (`schlass_mfa_challenge`, `schlass_mfa_enroll`) stay `SameSite=Strict` — never traverse cross-site redirects.

Auth middleware (`internal/auth/middleware.go`) reads cookie, fetches user fresh from PG every request (no session denormalization), injects via `users.WithCurrentUser(ctx, u)`. The user context key + `users.CurrentUser(ctx)` reader live in `internal/users/context.go`, shared by session + bearer middleware.

**Enumeration defense.** Login pre-computes a dummy Argon2id hash in `auth.NewHandler` + runs `crypto.VerifyPassword` against it on user-not-found. Rate limit 5/min per IP. Account lockout via `users.failed_login_attempts` + `users.locked_until` with concurrent-safe `UPDATE ... WHERE (locked_until IS NULL OR locked_until < now()) RETURNING ...`. `ResetFailedLogins` refuses to clear active lock.

*Known gap, accepted:* post-hash pipeline diverges (~4ms) between known-wrong-password + unknown-user. Revisit when multi-user surface widens.

**PostLogin branch order**: (a) `force_password_change=true` → session + AuthGuard routes `/change-password`; (b) `mfa_required + not enrolled` → enrollment flow (202 + enroll cookie, no session); (c) `mfa_required + enrolled` → challenge (202 + challenge cookie, no session); (d) legacy → session. Temp password must rotate before MFA binding.

**Audit interfaces.** `internal/audit/logger.go` declares both `audit.Logger` (narrow — `Log(ctx, q, entry)`) and `audit.PseudonymizingLogger` (wide — adds `PseudonymizeUser`). Most features depend on the narrow one; `auth/` and `users/` depend on the wide one for GDPR erasure. `*audit.Store` satisfies both.

**Router**: `internal/server/router.go` `BuildRouter(RouterDeps) (http.Handler, error)`. Both `cmd/schlass/main.go` + `test/integration/testutil.go` use it. `RouterDeps.AuditStore` field is `audit.PseudonymizingLogger` so integration tests can inject a fake.

**Session-terminate asymmetry.** `DELETE /api/users/:id/sessions` (all sessions) bumps `user:revoke_before` — full identity revocation. `DELETE /api/users/:id/sessions/:token` (single device) deliberately does NOT bump — admin-web session token can't map to specific OIDC token; bumping would revoke all OIDC tokens regardless of device. Do not "fix".

### Password reset

`POST /api/password-reset/request` enumeration-safe — always 200 empty body. Dummy-Argon2id timing parity. Rate limit via `SCHLASS_PASSWORD_RESET_RATE_LIMIT` (5/min default). Tokens 32-byte `crypto/rand` base64url; only HMAC-SHA256 hash stored. Email fire-and-forget post-commit goroutine — no retry queue in v1. `POST /api/password-reset/confirm` validates under `SELECT ... FOR UPDATE` (not-found/expired/used all → `INVALID_TOKEN`), hashes new password, updates user, marks used, audits `password_reset.completed`, post-commit bumps `revoke_before` + wipes Valkey sessions. No rate limit on confirm; token possession = auth. Audit events: `password_reset.requested` `{email_matched, token_id?, email_hash_prefix?}`, `password_reset.completed` `{token_id}`.

**super_admin cannot self-reset via email.** ENISA NIS2 (Jun-2025) mandates phishing-resistant MFA for privileged accounts; email reset links are phishable. `PostRequest` checks `user.Role == "super_admin"` after dummy-verify + after `matched` set, routes through unmatched path (no mint, no email, 200). Separate audit `password_reset.admin_blocked` `{reason: "super_admin_cannot_self_reset"}` for forensics.

**super_admin recovery path.** Another super_admin resets via `POST /api/users/:id/reset-password`. When none exists, operator CLI `schlass recovery-reset --email <addr>` mints 1h single-use token gated by `SCHLASS_RECOVERY_MODE=1`. Impl: `internal/recovery/reset.go` (`Run` = CLI, `Execute` = testable core). Audit `password_reset.recovery_issued`, `actor_email="system:recovery"`, `{token_id, target_email, invoker:{hostname, os_user}}`. Runbook: `docs/operator/recovery.md`.

**Token hashes HMAC-peppered.** `token_hash` = `HMAC-SHA256(pepper, plaintext)`. Pepper = HKDF from `SCHLASS_ENCRYPTION_KEY`, `info="password_reset_token_hmac_pepper"`, 32 bytes, re-derived at startup (no persistence). Constructor panics if pepper not 32 bytes. Migration 000020 force-expires all outstanding tokens on deploy (plaintext unrecoverable).

**Nightly sweeper.** `internal/server.StartSweeper` ticker bound to main ctx; each tick deletes `password_reset_tokens expires_at < now() - 30d` + `authorization_codes expires_at < now() - 7d` in one tx, writes single `password_reset.cleanup_swept` audit row `{reset_rows_deleted, auth_code_rows_deleted}`. Interval 24h default; `SCHLASS_SWEEPER_INTERVAL_SECS` (0 disables). `RunSweepOnce` exported for tests.

### OIDC authorization server

OAuth 2.1 + OIDC Core. Endpoints: `GET /authorize` (authorization_code + PKCE S256 mandatory, `state` required, exact-match redirect_uri), `POST /token` (authorization_code + refresh_token, `client_secret_post`), `GET /userinfo` (RS256 Bearer JWT, per-scope claims), `GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json`. Access tokens `typ=at+jwt`, ID tokens `typ=JWT`. Alg-confusion + `alg=none` rejected.

**Signing keys.** RSA-2048 in `signing_keys` table, one `active` + zero-or-more `retiring` + `retired`. Private keys AES-256-GCM-wrapped. Bootstrap generates active if none (`oidc.signing_key.generated`). `POST /api/admin/signing-keys/rotate` (`signing_keys.rotate` perm) promotes active → retiring, mints fresh active (`oidc.signing_key.rotated`). Retire sweep (startup + after rotation) moves past `15m + 24h + 30s` to retired (`oidc.signing_key.retired`). Retiring keys in JWKS; retired not.

**Refresh rotation.** Rotate-on-every-use (OAuth 2.1). Each family has `family_id`; successful refresh deletes presented + inserts fresh in same family. Replay detected → `oidc.refresh.reuse_detected`, revokes family, returns `400 invalid_grant`. Absolute expiry preserved (inherits `absolute_exp`).

**revoke_before cutoff.** Per-user Valkey key `user:revoke_before:<id>` (30d TTL). Written post-commit via `session.RevokeBeforeSetNow(...)` (rounds up to next second to close same-second race) by every "invalidate all sessions" path: admin disable, admin reset-password, admin reset-mfa, self change-password, self disable-mfa. Each write inserts `user.revoke_before_set` in the mutation tx. Enforced at `/token` refresh + bearer middleware (`internal/authserver/bearer_middleware.go`) via strict `<` vs `iat`. Reject writes `user.revoke_before_enforced` (best-effort) + returns `invalid_grant`/`invalid_token`.

**return_to threading.** Three state carriers: MFA Valkey hashes (`mfa:enroll:<t>`/`mfa:challenge:<t>` field `return_to`), `Session.PendingReturnTo` for force-password-change, terminal JSON `redirect_to`. Every ingress + egress revalidates via `oidc.SanitizeReturnTo` (scheme+host match `SCHLASS_PUBLIC_URL` or empty; path must equal `/authorize`) — fails closed.

**`POST /api/change-password` returns 200 with `{redirect_to?}`**, not 204.

**Dev-seed.** `internal/server.SeedDevClient` runs at startup when `SCHLASS_DEV=1` AND `SCHLASS_PUBLIC_URL` scheme is `http://`. Upserts `dev-test-client` confidential (scopes `openid profile email offline_access`, grants `authorization_code refresh_token`). Secret = `SCHLASS_DEV_SECRET` if set (Playwright), else 32 random base64url; Argon2id-hashed; INFO-logged once. Never runs under HTTPS. Re-invocation refreshes shape without touching `secret_hash`.

### OIDC client management + signing keys UI

Admin CRUD `/api/clients/*` (list/get/create/update/disable/enable/rotate-secret/delete) gated by eight `clients.*` perms. Handler: `internal/clients/handler.go`. Write handlers = audit-in-tx identical to `users/handler.go` — per-field audit rows on PATCH (`client.name_updated`, `client.redirect_uris_updated`, `client.scopes_updated`, `client.grants_updated`) in canonical order inside tx. `SELECT ... FOR UPDATE` on client row serializes PATCHes.

**Secret rotation overlap.** `POST /api/clients/:id/rotate-secret` mints 32-byte secret, moves existing hash to `secret_hash_previous` with `secret_previous_expires_at = now() + 24h`, returns plaintext ONCE. `VerifySecret` tries current-then-previous during grace. Second rotation discards previous. Constant `clientSecretOverlapTTL` in `internal/clients/handler.go` — move to instance_config when variable. ~30ms timing side-channel accepted.

**Hard delete safe.** Migration 000017 drops `audit_logs.client_id` FK + adds `ON DELETE CASCADE` on `authorization_codes.client_id`. `DELETE /api/clients/:id` = PG delete + `client.deleted` audit in one tx, post-commit `session.RevokeBeforeClientSetNow(...)`. Bearer middleware + `/token` refresh read cutoff via `session.RevokeBeforeClientGet` + reject `iat`-before tokens. PG delete is load-bearing; Valkey best-effort.

**Scope + grant re-validation.** `/token` auth_code + refresh grants re-intersect token scopes against current `client.allowed_scopes` via `intersectScopesAgainstClient` (empty → `invalid_scope`). Grant removal → `unauthorized_client`.

**Admin UI.** `/admin/clients` (list with Active/Disabled/All filter pills), `/admin/clients/new` (permissive defaults), `/admin/clients/:id` (read-first detail + inline Edit + Rotate + Danger zone Disable/Enable/Delete type-to-confirm), `/admin/signing-keys` (Rotate button + lifecycle explainer; no retiring list or JWKS viewer in v1). `ClientSecretModal` (reveal-once, analog of `TempPasswordModal`) after create + rotate. **Never add "View audit log" stub links** until audit-log view ships.

Validators: `internal/clients/validate.go` (`ValidateClientName` 1-100, `ValidateScopes` ⊆ `{openid, profile, email, offline_access}`, `ValidateGrantTypes` ⊆ `{authorization_code, refresh_token}`), `internal/clients/redirect_uri.go` (`ValidateRedirectURIInput`: https OR http+loopback per RFC 8252, 2048-byte cap, no fragment, no wildcards). All admin write handlers: `http.MaxBytesReader(64KB)` + `json.DisallowUnknownFields()`. Only `confidential` supported in v1; `public` additive later. `private_key_jwt`/mTLS out of scope.

**RP integration — PKCE mandatory.** OAuth 2.1 PKCE S256 enforced on every auth_code flow including confidential clients. Grafana: set `GF_AUTH_GENERIC_OAUTH_USE_PKCE=true`. Without: `invalid_request` "PKCE S256 required".

### Authorization

Permission-string at middleware layer. Every protected route gated by `users.RequirePermission("<resource>.<action>")` — not raw role checks. Role→permissions map: `internal/users/permission.go` (`rolePermissions`). v1 hardcodes `super_admin` → all 10 `users.*` + 8 `clients.*` + `signing_keys.rotate`; `user` → none. v2 replaces map with DB lookup; handler + SPA `usePermission` calls survive unchanged.

Handlers never inspect `user.Role` for authorization. Role reads permitted only for non-authorization (e.g. self-op guards) + must comment why.

SPA: `<AdminGuard>` at route level in `web/src/App.tsx` (non-super_admin → `/account`, unauthed → `/login`). `usePermission(PERMISSIONS.XXX)` hook in `web/src/features/auth/usePermission.ts` for button-level. Role-string checks reserved for display (`<RoleBadge>`, admin-count metrics) — must not gate destructive actions.

Post-auth routing: `LoginPage.handleSubmit` + `ChangePasswordForm` branch on role: `super_admin` → `/admin`, else `/account`. Root `/` uses `RootRedirect` inside `Bootstrap` with same branching.

Destructive handlers call `rejectSelfOp` first (400 `CANNOT_OPERATE_ON_SELF`). Last-admin lockout: `SELECT id FROM users WHERE role = 'super_admin' FOR UPDATE` serializes concurrent destructive ops + enable/disable flips (omitting `status=active` is deliberate), plus post-op count check in same tx. Shared helpers in `internal/users/handler.go`: `lockSuperAdminsForUpdate`, `remainingActiveSuperAdmins`, `enforceLastAdminLockout`, `rejectSelfOp`.

### Temporary Passwords

Admin-created users get server-generated 16-char temp password (`internal/crypto/password.go:GenerateTemporaryPassword`). Alphabet base58-minus-ambiguous (no `0/O/I/l/1`), ~93 bits entropy. Returned once in HTTP body, never stored/logged/audited. `force_password_change=true`. Used by `POST /api/users` + `POST /api/users/:id/reset-password` — admins never type passwords.

### MFA — TOTP enrollment + challenge

When `mfa_required=true`, unenrolled users complete 3-step wizard before session; enrolled users pass challenge every login. Stateless in PG until commit points; transient state in Valkey hashes keyed by opaque cookie token.

**Enrollment (`schlass_mfa_enroll` cookie):**

1. `POST /api/mfa/enrollment/start` — generates 160-bit TOTP secret (`crypto/rand` base32), Valkey hash, returns `{secret_base32, provision_uri}`. Idempotent; 10min TTL.
2. `POST /api/mfa/enrollment/verify` — verifies first code (max 5 attempts before nuke), generates 10 recovery codes (`XXXX-XXXX`, base58-minus-ambiguous, ~46 bits, Argon2id-hashed), returns plaintext once.
3. `POST /api/mfa/enrollment/complete` — requires `{acknowledged:true}`. Atomic: `SetTOTPEnrolled` (AES-GCM secret + `totp_enrolled_at` + counter reset), `RecoveryCodeStore.Insert`, `mfa.enrollment_completed`. On commit: destroys Valkey key, clears cookie, creates session. Audit-in-tx commit point.

**Challenge (`schlass_mfa_challenge` cookie, 120s TTL):**

`POST /api/login` for enrolled user sets challenge cookie, Valkey hash `{user_id, attempts_remaining=5}`. `POST /api/mfa/challenge`:
- TOTP (`{code}`): decrypt secret, `ValidateTOTP` ±1 step skew + `lastCounter` replay gate. Success: `AdvanceTOTPCounter` + `login.succeeded` + `mfa.challenge_succeeded` in one tx, create session.
- Recovery (`{recovery_code}`): load all unused, iterate constant-time (no early exit — prevents count enumeration), burn matched via `MarkUsed` + 3 audit rows in one tx, create session.

Attempts decremented atomically (`HIncrBy ... -1`) before verification. `attempts_remaining < 0` → Valkey key deleted + `MFA_CHALLENGE_MAX_ATTEMPTS`.

**Admin MFA reset.** `POST /api/users/{id}/reset-mfa` (`users.reset_mfa`) clears `totp_secret_encrypted`, `totp_enrolled_at`, `last_used_totp_counter`, deletes all recovery codes atomically. Audit: `mfa.reset`.

**Dual-auth enrollment.** `/api/mfa/enrollment/*` resolve principal from either `schlass_mfa_enroll` cookie OR authed session with `force_mfa_enrollment=true`. Session path: `/start` mints enrollment cookie inline + stamps `session_authed=1` so `/complete` skips `sessionStore.Create`. Fixes setup-wizard infinite redirect. See `resolveEnrollPrincipal`.

**Key files:** `internal/auth/mfa.go`, `internal/crypto/totp.go` (`GenerateTOTPSecret`, `ValidateTOTP`, `BuildProvisionURI`), `internal/crypto/recovery_codes.go` (`GenerateRecoveryCodes`), `internal/auth/recovery_code_store.go` (`Insert/ListUnused/CountUnused/MarkUsed/DeleteAllForUser`), `internal/users/store.go` (`SetTOTPEnrolled/AdvanceTOTPCounter/ClearTOTPEnrollment`).

**Rate limit.** `POST /api/mfa/challenge` has own 5/min per-IP limiter. Override via `SCHLASS_MFA_CHALLENGE_RATE_LIMIT` (integer; 0 = default 5). E2E sets 1000 via `docker-compose.e2e.yml`; integration sets `MfaChallengeRateLimit: 10000`.

**Frontend:**
- `/setup-mfa` — `TotpEnrollmentWizard` (Scan QR → Verify → Acknowledge). Uses `qrcode.react` (ESM/React 19 compatible; do NOT swap for `react-qr-code` v2 — CJS Babel breaks Vite prod builds). Post-complete: super_admin → `/admin`, else `/account`.
- `/mfa-challenge` — `TotpChallengePage`. TOTP (6-digit `SixDigitInput`) + recovery (plain text, XXXX-XXXX placeholder). Recovery input must NOT `.toUpperCase()` — alphabet mixed-case + hashes case-sensitive.

**`/api/me` MFA fields.** `GetMe` includes `totp_enrolled_at` + `mfa.unused_recovery_codes` if enrolled.

## Database

### Two Roles

- `schlass_migrations` — owns tables, runs DDL. Startup only.
- `schlass_app` — runtime. All tables SELECT/INSERT/UPDATE/DELETE EXCEPT `audit_logs` (SELECT + INSERT only). RLS enforced.

Migrations auto-run at startup via `database.RunMigrations()`. Embedded from `internal/database/migrations/`.

### Audit Log Tamper Protection

`audit_logs` append-only at DB level:
- RLS: only SELECT + INSERT policies
- UPDATE + DELETE revoked from PUBLIC
- `schlass_app` granted SELECT + INSERT only

Compliance claim — never weaken.

**GDPR Art. 17 pseudonymization.** Single exception = `audit_log_pseudonymize_user(uuid)`, `SECURITY DEFINER` function owned by `schlass_migrations` (migration 000018), replaces `actor_email` with `'deleted:<uuid>'` on rows where `actor_id = <uuid>`. `schlass_app` has EXECUTE only — cannot UPDATE directly. Called inside `DELETE /api/users/:id`. Scope narrow: `actor_email` column only, not JSONB metadata. Never grant UPDATE on `audit_logs`; never add more `SECURITY DEFINER` functions without compliance review.

## Security Defaults

- MFA required by default (`mfa_required = true`)
- Password policy: min 12 chars, require uppercase + digit
- Argon2id: 19 MiB, 2 iter, 1 parallel
- AES-256-GCM envelope encryption for sensitive blobs (`smtp_password`, `totp_secret_encrypted`, signing-key PEMs). Ciphertext = `[0x01][wrapped DEK 60B][sealed data]`: random per-message DEK seals data, wrapped under operator KEK. AAD binds blob to storage slot (e.g. `instance_config:smtp_password`, `user_totp_secret:<user_id>`, `signing_key:private_pem`). Legacy v0 single-layer blobs still decrypt for back-compat — remove once all prod rows re-encrypted.
- KEK from `SCHLASS_ENCRYPTION_KEY` (32-byte base64). Rotate: unwrap DEKs with old KEK, rewrap with new — plaintext untouched. CLI tooling pending.
- Security headers (HSTS, CSP, X-Frame-Options, etc.) on all responses.
- Structured JSON logging always. No text mode.

### Email canonicalization

`users.email` stored lowercase, enforced twice:

- **Handler**: `setup.go`, `users.go` (Create/Update), `auth.go` PostLogin lowercase `req.Email` after `ValidateEmail`, before any store call.
- **DB**: migration 000012 replaces inline UNIQUE with `UNIQUE INDEX ON users(LOWER(email))` — direct SQL bypass still fails 23505.

`Alice@example.com` = `alice@example.com`. Never reintroduce case-sensitive comparison.

## Testing

- Unit: alongside code in `internal/*/`
- Integration: `test/integration/` with `testcontainers-go` (real PG + Valkey, no mocks)
- E2E: `web/e2e/` with `@playwright/test` against dockerized stack
- `make test` / `test-unit` / `test-integration` / `e2e`

E2E is the only tier exercising the shipping artifact in a real browser — integration via `httptest.NewRecorder` does not evaluate CSP, SameSite, or SPA bootstrap.

Never mock the database. Use testcontainers.

## Build

- `make build` — SPA + Go binary (`bin/schlass`)
- `make dev` — `docker compose up --build`
- `make dev-frontend` — Vite HMR (proxies `/api` → Go `:3000`)
- `make build-docker` — Docker image

### Local email testing (Mailpit)

`docker-compose.yml` ships Mailpit (`axllent/mailpit`). SMTP `:1025`, UI `http://localhost:8025`. Not wired by default — configure via `/admin/settings > Email` (Host `mailpit`, Port `1025`, no auth, From `no-reply@schlass.local`). Mailpit is a sink (doesn't deliver) — use Brevo/Mailgun/SES + SPF/DKIM for real deliverability.

## Frontend

- Feature-based: `web/src/features/<feature>/`
- Shared UI: `web/src/components/ui/` (shadcn copy-and-own)
- API: `web/src/lib/api.ts` — typed `apiFetch<T>()`
- i18n: `react-i18next`, `web/src/i18n/locales/{en,fr,de}.json`
- Backend → error codes; frontend translates via `t(\`errors.\${code}\`)`
- Tests: Vitest + RTL (`cd web && npm test`)

### Design System

Primary = teal (oklch); variables in `web/src/index.css`. Dark mode via `.dark` class on `<html>`; `ThemeToggle` cycles light/dark/system. `AuthLayout` wraps setup/login/change-password.

Typography: 24px auth titles, 20px admin card titles, 18px page titles, 14px default, 13px secondary, 12px labels/badges. Heights: 32px controls, 36px auth submit + row avatars, 24px badges. All colors from oklch tokens (`--primary/accent/destructive/warning/muted/border`). **No hex values in components.**

Install shadcn: `npx shadcn@latest add <name>`.

### i18n

- Languages: English (default), French, German
- All user-facing strings via `t()`
- Detection: browser → localStorage (`schlass-language`)
- Add new strings to all 3 locale files

## Setup for New Clones

```bash
make setup    # npm install + git hooksPath=.githooks/
```

Pre-commit runs: Go lint, Go unit tests, ESLint, Vitest.

## Commits

- Conventional commits: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `chore:`, `ci:`
- Branch: `<type>/<slug>` — slug is 2-4 kebab-case words describing *what* (e.g. `feat/admin-login`, `fix/ci-lint`). No sprint tags in branch names.
- Don't commit `.env`, `node_modules/`, `bin/`, `internal/web/dist/*` (except `.gitkeep`)

## Multi-Agent Workflow

Claude Code + Codex CLI share this repo. Both read this file (Codex via `AGENTS.md` → symlink to `CLAUDE.md`). Never edit `AGENTS.md`; edit `CLAUDE.md`.

**Division of labor**
- **Claude** — brainstorm, architecture, UI mockups, tricky cross-cutting refactors, final merge-readiness review.
- **Codex** — mechanical implementation from a scoped plan, large-PR adversarial review, backend debugging, one-shot-able tasks.

**Handoff protocol**
1. Claude writes plan to `docs/plans/<feature>.md` (spec, dependency map, step-by-step logic, constraints). Commit it on the feature branch.
2. Hand the branch + plan path to Codex. Repo IS the handoff state — no pasted blobs.
3. Codex implements; pushes; opens PR.
4. Claude reviews PR against plan + architecture.md.
5. Delete plan file in final commit before merge.

**Review handoff (this branch or any PR)**
- Invoke: `codex review <branch>` or open PR and `codex exec "review PR <n> against docs/architecture.md"`.
- Codex must flag: divergence from documented layout, dead shims, broken imports, test gaps, silent error paths.
- Claude reviews Codex's review — second-pass catch.

**Rule**: any behaviour or convention that outlives the session goes in CLAUDE.md, not chat memory. Any decision that only matters for one feature goes in `docs/plans/<feature>.md` and is deleted on merge.
