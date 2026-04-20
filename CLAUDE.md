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

### Config mutation audit rule

Every handler that writes to `instance_config` must audit `config.<key>.changed` inside the same Postgres transaction as the write, following the Audit-in-tx rule above. `instance_config` is where security policy lives (MFA requirement, password policy, lockout thresholds, signing key ops, SMTP, token TTLs — see `docs/v1-scope.md` §"Security & Instance Configuration"). Configuration changes are the audit trail item regulators scrutinize most; there is no acceptable "best-effort" exception analogous to middleware session revocation.

This rule is implemented by `internal/handler/settings.go` (Sprint 6b M5). The four `PATCH /api/settings/:domain` endpoints (General, Security, Tokens, Email) each emit one `config.<key>.changed` audit row per changed field inside the same PG tx as the `instance_config` write. Integration tests in `test/integration/settings_test.go` assert atomicity and no-op skip (unchanged values write no audit row). `smtp_password` is the only field whose audit metadata is `{"changed": true}` rather than `{"old_value", "new_value"}` — never leak plaintext/ciphertext. When adding new admin config fields, follow the `settings.go` pattern: snapshot pre-values → build change list → open tx → loop write+audit → commit. Never grant a config-writing code path that bypasses audit-in-tx.

### Sessions & Auth (Sprint 2+)

Admin UI uses a **first-party opaque-token session** — not OIDC. Login issues a 32-byte random token (base64url, `crypto/rand`), stored in Valkey as `session:<token>` → `{"user_id":"..."}` with a 24h sliding TTL. Cookie attributes: `HttpOnly; SameSite=Lax; Path=/; MaxAge=86400`; the `Secure` flag is toggled by the `SCHLASS_PUBLIC_URL` scheme at handler construction time (true iff `https://`). **`SameSite=Lax` (not `Strict`) is deliberate** — `/authorize` is an entry point for cross-site top-level redirects from OIDC relying parties, and `Strict` would hide the session cookie on that navigation, force a duplicate login, and leak dangling sessions. Lax still rejects the cookie on cross-site sub-resource requests and on cross-site POST/PATCH/DELETE, which is the CSRF threat model the flag protects against. MFA challenge/enrollment cookies (`schlass_mfa_challenge`, `schlass_mfa_enroll`) stay `SameSite=Strict` — they never traverse cross-site redirects.

The auth middleware (`internal/middleware/auth.go`) reads the cookie, fetches the user fresh from Postgres on every request (no denormalization of email/role/status into the session), and injects via `middleware.CurrentUser(ctx)`. Disabled users are revoked in-middleware with a `session.revoked` audit row.

**Audit-in-tx rule.** Login success/failure and logout write their audit rows *inside the same PG transaction* as the state change (counter increment/reset, session destruction). The tx commits before any Valkey side-effect (`session.Create` for login, `session.Delete` for logout), so "state change with no audit" is impossible by construction; the reverse ("audit with no Valkey effect") produces only a retry, not a compliance gap. See `internal/handler/setup.go:100-147` and `internal/handler/auth.go PostLogin/PostLogout` for the reference implementations.

**Documented exception — middleware session revocation is best-effort.** When the auth middleware detects an orphan session (user row gone) or a disabled user, it writes a `session.revoked` audit row via `_ = auditStore.Log(...)` (return value ignored, ERROR-level `slog` on failure) and unconditionally deletes the Valkey session. This is deliberately different from the audit-in-tx rule for two reasons: (a) the load-bearing compliance event is the original *user-disable* action at its source (Sprint 4+), not the subsequent cleanup in the middleware; (b) making middleware revocation audit-in-tx would wedge every authed request on PG errors, trading availability for a duplicate audit row. **Do not "fix" this to audit-in-tx** — it would break the "PG blip must not force-logout active users" property.

**Enumeration defense.** The login handler pre-computes a dummy Argon2id hash in `NewAuthHandler` and runs `crypto.VerifyPassword` against it on the user-not-found path so response timing matches the real password-verify path. Rate limiting is 5 requests per minute per IP on `POST /api/login`. Lockout is account-keyed via `users.failed_login_attempts` + `users.locked_until` with a concurrent-safe `UPDATE ... WHERE (locked_until IS NULL OR locked_until < now()) RETURNING ...` pattern in both `IncrementFailedLogins` and `ResetFailedLogins` (the latter refuses to clear an active lock, preserving the lockout duration against concurrent races).

**Known limitation — enumeration timing parity is imperfect.** The dummy-hash trick equalizes the Argon2id cost between the known-wrong-password and unknown-user paths, but the post-hash pipeline diverges: known-wrong does an extra `IncrementFailedLogins` UPDATE plus a richer audit row, which adds ~4ms on localhost (measured during the Sprint 2 security audit). Network jitter swamps this in practice, but a well-connected attacker with millions of probes could statistically distinguish the two states. This is an accepted trade-off for Sprint 2's single-admin threat model — an attacker already knows an admin exists, so the enumeration surface is moot. Revisit when Sprint 5+ adds multi-user management and the surface widens; the likely fix is to run a no-op UPDATE against a fake user id in the unknown-user path to equalize the full pipeline, not just the crypto step.

**PostLogin branch order.** The handler honours `force_password_change` BEFORE MFA state: a user with a temp password completes password rotation first, then the subsequent `/api/me` + `AuthGuard` cycle routes them into MFA enrollment if needed. The branch order is (a) `force_password_change=true` → session issued, AuthGuard routes to `/change-password`; (b) `mfa_required + not enrolled` → enrollment flow (202 + enrollment cookie, no session); (c) `mfa_required + enrolled` → challenge flow (202 + challenge cookie, no session); (d) legacy (no MFA) → session issued immediately. Enrolling MFA against a temp password would bind the authenticator to a credential that's about to change — backwards per every major 2026 provider. See `internal/handler/auth.go` `PostLogin`.

**AuditLogger interface.** `internal/handler/auth.go` defines `type AuditLogger interface { Log(ctx, q, entry) error }` (exported) so the router wiring and integration test harness can inject a fake audit store. `*store.AuditStore` satisfies the interface unchanged. `internal/middleware/auth.go` defines a parallel unexported interface of the same shape (middleware cannot import handler without a circular dep).

**Router wiring lives in `internal/server/router.go`** via `BuildRouter(RouterDeps) (http.Handler, error)`. Both `cmd/schlass/main.go` and `test/integration/testutil.go` use this single function — any future route or middleware change lands in one place and both production and tests pick it up.

End-user (third-party client) OIDC sessions are a separate mechanism — see the OIDC authorization server section below. Admin web sessions never interact with OIDC refresh tokens; the two credential stores are fully independent.

**Session-terminate asymmetry.** `DELETE /api/users/:id/sessions` (all-sessions nuclear terminate) bumps `user:revoke_before` because it's a full session-identity revocation — every outstanding OIDC access + refresh token for the user must fail on next use. `DELETE /api/users/:id/sessions/:token` (single-device terminate) deliberately does NOT bump `revoke_before`: an opaque admin-web session token cannot map to a specific OIDC token, and bumping revoke_before there would revoke every OIDC token regardless of device, contradicting the "sign out my other laptop" intent. This asymmetry is correct; do not "fix" it to match.

### OIDC authorization server (Sprint 4+)

Self-hosted OIDC provider implementing OAuth 2.1 + OIDC Core: `GET /authorize` (authorization_code + PKCE S256 mandatory, `state` required, exact-match `redirect_uri` whitelist), `POST /token` (authorization_code and refresh_token grants, `client_secret_post` auth), `GET /userinfo` (RS256 Bearer JWT, per-scope claims), `GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json`. Access tokens carry `typ=at+jwt`, ID tokens `typ=JWT`; alg-confusion and `alg=none` are rejected at verify.

**Signing keys.** RSA-2048 keypairs in `signing_keys` table, one `active` + zero-or-more `retiring` + `retired` at any time. Private keys AES-256-GCM-wrapped against `SCHLASS_ENCRYPTION_KEY`. Bootstrap at startup generates an active key if none exists (`oidc.signing_key.generated`). `POST /api/admin/signing-keys/rotate` (gated by `signing_keys.rotate` permission) promotes the active key to `retiring` and mints a fresh active (`oidc.signing_key.rotated`). The retire sweep (runs at startup + after each rotation) moves keys past `15m + 24h + 30s` from `retiring` to `retired` (`oidc.signing_key.retired`). Retiring keys appear in JWKS to validate outstanding tokens; retired keys do not.

**Refresh rotation.** OAuth 2.1 rotate-on-every-use. Each refresh-token family carries a `family_id`; a successful `/token` refresh grant deletes the presented token, inserts a fresh one in the same family, and returns it. A replay of a rotated refresh is detected (`oidc.refresh.reuse_detected`), revokes the entire family, and returns `400 invalid_grant`. Absolute expiry is preserved across rotations (new refresh inherits the family's `absolute_exp`).

**revoke_before cutoff.** Per-user timestamp in Valkey (`user:revoke_before:<id>`, 30d TTL). Written post-commit via `revokebefore.SetNow(...)` (rounds up to next whole second to close the same-second mutation/token race) by every handler that "invalidates all outstanding sessions": admin disable, admin reset-password, admin reset-mfa, self change-password, self disable-mfa. Each write also inserts a `user.revoke_before_set` audit row in the mutation's PG tx. Enforced at `POST /token` refresh grant and in the bearer auth middleware (`internal/middleware/bearer_auth.go`) via strict `<` compare against `iat`. A rejected token writes `user.revoke_before_enforced` (best-effort) and returns `invalid_grant` / `invalid_token`.

**return_to threading.** Three coexisting state carriers (spec §7): MFA enrollment/challenge Valkey hashes (`mfa:enroll:<t>` / `mfa:challenge:<t>` under field `return_to`), `Session.PendingReturnTo` for the force-password-change branch, and the terminal JSON response field `redirect_to`. Every ingress and egress revalidates through `handler.SanitizeReturnTo` (scheme + host must match `SCHLASS_PUBLIC_URL` or be empty; path must equal `/authorize`) — open-redirect guard fails closed. **Breaking change (Sprint 4):** `POST /api/change-password` now returns `200 OK` with `{ "redirect_to"?: string }` instead of `204 No Content`. SPA `apiFetch<void>` consumers unaffected.

**Dev-seed.** `internal/bootstrap.SeedDevClient` runs at startup when `SCHLASS_DEV=1` AND `SCHLASS_PUBLIC_URL` scheme is `http://`. Upserts a single `dev-test-client` confidential client with scopes `openid profile email offline_access` and grants `authorization_code refresh_token`. Secret plaintext is `SCHLASS_DEV_SECRET` if set (used by `docker-compose.e2e.yml` so Playwright knows the value) or 32 random base64url bytes; Argon2id-hashed before storage and logged once at INFO. Never runs under HTTPS to prevent poisoning prod DBs. Re-invocation refreshes shape (scopes, grants, redirect URIs) in-place without touching `secret_hash`.

### OIDC client management + signing keys UI (Sprint 5+)

Admin CRUD over `/api/clients/*` (eight endpoints: list / get / create / update / disable / enable / rotate-secret / delete) gated by eight `clients.*` permissions under the `super_admin` role (see `internal/middleware/permission.go`). Handler code in `internal/handler/clients.go`; write handlers follow the audit-in-tx rule identical to users.go — per-field audit rows on PATCH (`client.name_updated`, `client.redirect_uris_updated`, `client.scopes_updated`, `client.grants_updated`) inserted in canonical order inside the tx, and a `SELECT ... FOR UPDATE` on the client row serializes concurrent PATCHes to prevent lost updates.

**Secret rotation overlap.** `POST /api/clients/:id/rotate-secret` mints a 32-byte `crypto/rand` secret (base64url, Argon2id-hashed), moves the existing secret hash into `secret_hash_previous` with `secret_previous_expires_at = now() + 24h`, and returns the plaintext ONCE in the response body. `VerifySecret` now tries current-then-previous (if the window hasn't expired) — both succeed during the grace period. Second rotation discards any existing previous (documented behavior, no "revoke previous early" endpoint). The 24h constant lives as `clientSecretOverlapTTL` in `internal/handler/clients.go`; move to instance_config when a use case needs variability. The ~30ms Argon2id cost difference between current-match (1 op) and previous-match (2 ops) is an accepted timing side-channel — consistent with the Sprint 2 enumeration-timing precedent; attacker already knows which secret they presented.

**Hard delete is safe.** Migration 000017 drops `audit_logs.client_id` FK (precedent: migration 000011 for `actor_id`) and adds `ON DELETE CASCADE` on `authorization_codes.client_id`. `DELETE /api/clients/:id` commits the PG delete + `client.deleted` audit row in one tx, then post-commits `revokebefore.ClientSetNow(ctx, valkey, clientID)` — mirror of the per-user revoke_before. `bearer_auth` middleware and `/token` refresh grant both read the cutoff (via `revokebefore.ClientGet`) and reject tokens whose `iat` is before it. Best-effort on the Valkey write; PG delete is the load-bearing compliance event.

**Scope + grant re-validation.** `/token` auth_code + refresh grants now re-intersect the token's granted scopes against the current `client.allowed_scopes` via `intersectScopesAgainstClient` (returns `invalid_scope` on empty intersection). Grant-type removal (admin PATCHing `refresh_token` out of `client.allowed_grant_types`) returns `unauthorized_client`. Closes a Sprint 4 gap surfaced by Sprint 5 PATCH: without re-validation, a scope removed by an admin would continue to work on refresh until token expiry.

**Admin UI** at `/admin/clients` (list with Active/Disabled/All filter pills), `/admin/clients/new` (single-card form with permissive scope/grant defaults), `/admin/clients/:id` (read-first detail with per-section inline Edit + Rotate secret + Danger zone: Disable/Enable + Delete with type-to-confirm modal), and `/admin/signing-keys` (Rotate button + lifecycle explainer; no retiring-keys list or JWKS viewer in v1). The sidebar in `AdminLayout.tsx` has two new NavLinks for Clients + Signing keys, same height/radius/active-state as the existing Users link. `ClientSecretModal` (reveal-once, analog of `TempPasswordModal`) is shown after create + rotate — copy buttons + amber warning + single Done action. **Never add a "View audit log" stub link** to any page until the audit-log view ships — no UI for unimplemented features.

Validators live in `internal/model/client.go` (ValidateClientName 1-100, ValidateScopes ⊆ `{openid, profile, email, offline_access}`, ValidateGrantTypes ⊆ `{authorization_code, refresh_token}`) and `internal/handler/redirect_uri_validation.go` (ValidateRedirectURIInput: https OR http+loopback per RFC 8252, 2048-byte cap, no fragment, no wildcards). All admin write handlers use `http.MaxBytesReader(64KB)` + `json.DisallowUnknownFields()`. Only the `confidential` client type is supported; `public` (PKCE-only) is additive later via the existing `client_type` column (schema already allows it). `private_key_jwt` / mTLS (FAPI 2.0) remain out of scope; `token_endpoint_auth_method` column is forward-compatible.

**Third-party RP integration — PKCE is mandatory.** Schlass enforces OAuth 2.1 PKCE S256 on every `authorization_code` flow, including confidential clients. Some legacy OAuth 2.0 relying parties disable PKCE by default (e.g. Grafana's generic_oauth: set `GF_AUTH_GENERIC_OAUTH_USE_PKCE=true`). Without it, `/authorize` returns `invalid_request` with reason `"PKCE S256 required"` and the RP surfaces a generic "Login provider denied login request". Always enable PKCE on the RP side when wiring a new client.

### Authorization (Sprint 3+)

Authorization is permission-string shaped at the middleware layer. Every protected route is gated by `middleware.RequirePermission("<resource>.<action>")` rather than a raw role check. The role→permissions mapping lives in `internal/middleware/permission.go` as a package-level `rolePermissions` map; v1 hardcodes `super_admin` → all 10 `users.*` permissions and `user` → none. Dynamic role management (operator-created roles, per-permission toggles, an admin UI) is a v2 deliverable — see `docs/v1-scope.md` line 33, "Org Admin deferred to v2". When v2 lands, `rolePermissions` is replaced by a DB lookup against `roles` / `role_permissions` tables; handler gates and SPA `usePermission()` calls survive unchanged.

Handlers never inspect `user.Role` for authorization — the middleware has already decided. Handler-level role reads are permitted only for non-authorization purposes (e.g. a self-op guard that says "an admin cannot demote themselves"), and the call site must comment why.

The SPA mirrors the contract via two layers: `<AdminGuard>` at the route level in `web/src/App.tsx` (redirects non-super_admin to `/account`, unauthenticated to `/login`), and the `usePermission(PERMISSIONS.XXX)` hook in `web/src/features/auth/usePermission.ts` for button-level gates. Today the `users.*` UI has no button-level gates — all admin-only routes are protected at the route level and every non-admin redirect happens before the admin UI is reached. `usePermission` exists for future features that want to render differently per permission within a single route (e.g., a read-only view for users without `users.update`). Role-string checks in the SPA are reserved for display surfaces (e.g. the `<RoleBadge>` component, admin-count metrics) and must not gate destructive or privileged actions.

Post-authentication routing: `LoginPage.handleSubmit` branches on the authenticated user's role — `super_admin` → `/admin`, anyone else → `/account`. `ChangePasswordForm` applies the same branching after a forced password change so a `role=user` account isn't bounced to `/admin/users` and then redirected again by `AdminGuard`. The root `/` route uses a `RootRedirect` helper wrapped in `Bootstrap` that performs the same branching.

Destructive handlers (disable, delete, role-demote PATCH) call `rejectSelfOp` as their first action: it's cheap, fails fast with 400 `CANNOT_OPERATE_ON_SELF`, and avoids any DB work for the obvious cases. Last-admin lockout is enforced with a `SELECT id FROM users WHERE role = 'super_admin' FOR UPDATE` that serializes concurrent destructive operations on the admin set, followed by a post-operation count check inside the same transaction as the correctness backstop. The lock deliberately omits `status = 'active'` so it also serializes against concurrent enable/disable flips — narrowing it would let a parallel re-enable slip past the count check. The shared helpers — `lockSuperAdminsForUpdate`, `remainingActiveSuperAdmins`, `enforceLastAdminLockout`, and `rejectSelfOp` — all live in `internal/handler/users.go`. Sprint 4's client-management routes will reuse the same `RequirePermission` pattern, declaring new `clients.*` permission strings at route-wiring time.

### Temporary Passwords (Sprint 3+)

Admin-created users receive a server-generated 16-character temporary password (`internal/crypto/password.go:GenerateTemporaryPassword`). The alphabet is base58-minus-ambiguous-characters (no `0/O/I/l/1`), yielding ~93 bits of entropy. The plaintext is returned once in the HTTP response body and never stored, logged, or written to audit rows. `force_password_change=true` forces the user to rotate it on first sign-in. Both `POST /api/users` (create) and `POST /api/users/:id/reset-password` (admin reset) use this flow — admins never type passwords.

### MFA — TOTP enrollment and challenge (Sprint 3+)

**Overview.** When `mfa_required = true` in `instance_config`, users who are not enrolled must complete the 3-step enrollment wizard before receiving a session. Users who are enrolled must pass a TOTP or recovery-code challenge on every login. Both flows are stateless in PG until their respective commit points; transient state lives in Valkey hashes keyed by an opaque cookie token.

**Enrollment flow (3 steps, gated by `schlass_mfa_enroll` cookie):**

1. `POST /api/mfa/enrollment/start` — generates a 160-bit TOTP secret (`crypto/rand`, base32), stores it in the Valkey enrollment hash, returns `{ secret_base32, provision_uri }`. Idempotent: re-calling overwrites the secret and resets the 10-minute TTL.
2. `POST /api/mfa/enrollment/verify` — verifies the first TOTP code (max 5 attempts before token is nuked), generates 10 recovery codes (`XXXX-XXXX`, base58-minus-ambiguous alphabet, ~46 bits each, Argon2id-hashed), stashes the hashes in the enrollment hash, returns plaintext codes once.
3. `POST /api/mfa/enrollment/complete` — requires `{ acknowledged: true }`. Commits atomically: `SetTOTPEnrolled` (writes AES-GCM-encrypted secret + `totp_enrolled_at` + resets counter), `RecoveryCodeStore.Insert` (10 hashes), `mfa.enrollment_completed` audit row. On commit: destroys enrollment Valkey key, clears enroll cookie, creates a real session. This is the audit-in-tx commit point.

**Challenge flow (gated by `schlass_mfa_challenge` cookie, 120s TTL):**

`POST /api/login` for an enrolled user sets `schlass_mfa_challenge` instead of a session cookie, writing `user_id` + `attempts_remaining=5` to a Valkey hash keyed by the challenge token.

`POST /api/mfa/challenge` dispatches on request body:
- TOTP path (`{ code }`): decrypts secret, calls `ValidateTOTP` with `±1 step` skew and `lastCounter` replay gate. On success: `AdvanceTOTPCounter` + `login.succeeded` + `mfa.challenge_succeeded` in one tx, then creates session.
- Recovery path (`{ recovery_code }`): loads all unused codes, iterates all of them in constant time (no early exit — prevents timing-based enumeration of remaining count), burns the matched code via `MarkUsed` + 3 audit rows in one tx, then creates session.

Attempts are decremented atomically before any verification work (`HIncrBy ... -1`). When `attempts_remaining < 0`, the Valkey key is deleted immediately and `MFA_CHALLENGE_MAX_ATTEMPTS` is returned.

**Admin MFA reset:** `POST /api/users/{id}/reset-mfa` (`users.reset_mfa` permission) clears `totp_secret_encrypted`, `totp_enrolled_at`, `last_used_totp_counter`, and deletes all recovery codes atomically. The user is forced through enrollment again on next login. Audit: `mfa.reset`.

**Documented exception — challenge failed audit is best-effort.** `mfa.challenge_failed` rows are written in a separate short-lived tx (not the decrement tx). Failure is logged ERROR-level but does not block the response. This is consistent with the middleware-revocation exception rationale: the brute-force guard is the atomic decrement (structural), not the audit row (forensic). Do not "fix" this to audit-in-tx.

**Enrollment endpoints accept either auth mode.** `/api/mfa/enrollment/start|verify|complete` resolve the enrollment principal from either the `schlass_mfa_enroll` cookie (pre-session path — user just entered password and was bounced to enrollment) OR an authenticated session cookie whose user has `force_mfa_enrollment=true` (post-session path — setup-wizard admin, or a user who got admin-reset while holding an active session). When session-authed, `/start` mints an enrollment cookie inline and stamps `session_authed=1` on the Valkey state so `/complete` skips `sessionStore.Create` — the user already has a valid session. Without this dual-auth the setup wizard admin gets stuck in an infinite redirect between `/setup-mfa` and `/admin`. See `internal/handler/mfa.go` `resolveEnrollPrincipal`.

**Key files:** `internal/handler/mfa.go` (all handler logic), `internal/crypto/totp.go` (`GenerateTOTPSecret`, `ValidateTOTP`, `BuildProvisionURI`), `internal/crypto/recovery_codes.go` (`GenerateRecoveryCodes`), `internal/store/recovery_code_store.go` (`Insert`, `ListUnused`, `CountUnused`, `MarkUsed`, `DeleteAllForUser`), `internal/store/user_store.go` (`SetTOTPEnrolled`, `AdvanceTOTPCounter`, `ClearTOTPEnrollment`).

**Rate limiting.** `POST /api/mfa/challenge` has its own 5/min per-IP rate limiter independent of the login limiter. Override via `SCHLASS_MFA_CHALLENGE_RATE_LIMIT` env var (integer; 0 = default 5). This follows the same pattern as `SCHLASS_LOGIN_RATE_LIMIT`. E2E tests set this to 1000 via `docker-compose.e2e.yml`; integration tests set `MfaChallengeRateLimit: 10000` in `RouterDeps` via `test/integration/testutil.go`.

**Frontend routes:**
- `/setup-mfa` — `TotpEnrollmentWizard` (3-step: Scan QR, Verify code, Acknowledge recovery codes). Uses `qrcode.react` (ESM/React 19 compatible; do NOT replace with `react-qr-code` v2 which uses CJS Babel format incompatible with Vite production builds). After complete, `super_admin` lands on `/admin`, others on `/account`.
- `/mfa-challenge` — `TotpChallengePage`. Supports TOTP (6-digit `SixDigitInput`) and recovery-code mode (plain text input, XXXX-XXXX placeholder). Recovery code input must NOT apply `.toUpperCase()` — the alphabet is mixed-case and Argon2id hashes are case-sensitive.

**`/api/me` MFA fields.** `GetMe` includes `totp_enrolled_at` (from `userDTO`) and, if enrolled, `mfa.unused_recovery_codes` (from `RecoveryCodeStore.CountUnused`). The account page uses both: `totp_enrolled_at` to render the "Enabled" badge, `mfa.unused_recovery_codes` to display the remaining code count.

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

**GDPR Art. 17 pseudonymization path.** `audit_logs` is append-only to `schlass_app` — UPDATE and DELETE are revoked. The single exception is `audit_log_pseudonymize_user(uuid)`, a `SECURITY DEFINER` SQL function owned by `schlass_migrations` (introduced in migration 000018) that replaces `actor_email` with `'deleted:<uuid>'` on rows where `actor_id = <uuid>`. `schlass_app` has EXECUTE on this function only; it cannot UPDATE the table directly. Called inside `DELETE /api/users/:id` as the GDPR Art. 17(3)(b) bridge — the function and its call site are the *only* sanctioned mutation path on `audit_logs`. Scope is deliberately narrow (actor_email column only, not JSONB metadata fields such as `old_email`) — re-evaluate if a DPA request requires deeper scrubbing. Never grant UPDATE on `audit_logs` directly, and never add additional `SECURITY DEFINER` functions against this table without the same compliance-trade-off review.

## Security Defaults

- MFA required by default (`mfa_required = true`)
- Password policy: min 12 chars, require uppercase + digit
- Argon2id (19 MiB, 2 iterations, 1 parallelism) for password hashing
- AES-256-GCM for encrypting sensitive config (smtp_password, totp_secret)
- Encryption key from `SCHLASS_ENCRYPTION_KEY` env var (32-byte base64)
- Security headers on all responses (HSTS, CSP, X-Frame-Options, etc.)
- Structured JSON logging always (no text mode, dev/prod parity)

### Email canonicalization (Task 10/11)

`users.email` is stored lowercase, enforced at two layers:

- **Handler boundary** — `internal/handler/setup.go`, `internal/handler/users.go` (Create/Update), and `internal/handler/auth.go` (PostLogin) lowercase `req.Email` immediately after `ValidateEmail` and before any store call.
- **Database** — migration 000012 replaces the inline `UNIQUE` on `email` with a functional `UNIQUE INDEX ON users(LOWER(email))`, so a direct SQL insert that bypasses the handler still fails loudly with 23505 instead of creating a case-variant duplicate.

`Alice@example.com` and `alice@example.com` are the same user identity. Login is case-insensitive by construction. Never reintroduce a case-sensitive comparison on `users.email` — doing so would allow credential-recycling via case variation.

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

### Local email testing (Mailpit)

`docker-compose.yml` ships a Mailpit service (`axllent/mailpit`) alongside Postgres + Valkey for local SMTP testing. Mailpit exposes SMTP on `:1025` and a web UI on `http://localhost:8025`. Schlass is NOT wired to it by default — configure it via `/admin/settings > Email` (Host: `mailpit`, Port: `1025`, no auth, From: `no-reply@schlass.local`) then use the Test connection button or trigger the forgot-password flow. Every received message is viewable at `localhost:8025` with rendered HTML + source + attachments. Mailpit is a sink (accepts but does not deliver) — for real-world deliverability testing use a transactional provider (Brevo, Mailgun, SES) with SPF/DKIM on the instance domain.

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
