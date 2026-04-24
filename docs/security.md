# Security

## Status & disclosure

Schlass is a **pre-v1 personal portfolio project**. It has not been security-audited, battle-tested in production, or validated against real compliance audits. **Do not deploy it as your real identity layer.**

For bug reports or suspected vulnerabilities:

- Open a GitHub issue on the repo, or email the author listed in `git log`.
- There is no bounty program, no dedicated disclosure timeline, and no guaranteed response window — this is a solo maintainer.
- If you are evaluating Schlass for real use, the answer is don't; come back when v1 ships with a third-party audit.

The rest of this document catalogs the security controls currently implemented so that a security-aware reader can evaluate the design. Paths are relative to the repo root.

## Cryptography

- **Password hashing (Argon2id)** — 19 MiB, 2 iterations, parallelism 1, per-password random salt, PHC-encoded output. Defends against offline cracking of stolen hashes. `internal/crypto/password.go`
- **Encryption at rest for sensitive blobs** — AES-256-GCM envelope encryption keyed by `SCHLASS_ENCRYPTION_KEY`. Ciphertext layout: `[0x01][wrapped DEK 60B][sealed data]` — random per-message DEK seals the data, wrapped under the operator KEK. AAD binds each blob to its storage slot (`instance_config:smtp_password`, `user_totp_secret:<user_id>`, `signing_key:private_pem`) so a blob swapped between rows fails to decrypt. Legacy v0 single-layer blobs still decrypt for backward compatibility. `internal/crypto/encryption.go`
- **HMAC pepper for password-reset tokens** — `token_hash = HMAC-SHA256(pepper, plaintext_token)` where `pepper` is HKDF-derived from `SCHLASS_ENCRYPTION_KEY` (info string `password_reset_token_hmac_pepper`, 32 bytes, re-derived at startup — never persisted). A DB-only dump cannot be brute-forced without also exfiltrating the KEK. `internal/crypto/token_hmac.go`, `internal/auth/password_reset_token_store.go`
- **TOTP secrets** — 160-bit secret (`crypto/rand`, 20 bytes), base32-encoded (RFC 6238), stored AES-256-GCM encrypted in `users.totp_secret_encrypted`, decrypted only at challenge time. SHA1 / 6 digits / 30-second period. `internal/crypto/totp.go`
- **Recovery codes** — 10 single-use codes per enrollment, format `XXXX-XXXX` from a 57-char base58-minus-ambiguous alphabet (~46 bits per code). Argon2id-hashed with the same policy as passwords; plaintext returned once and never stored. `internal/crypto/recovery_codes.go`
- **HIBP breach-corpus check** — new passwords are k-anonymity-checked against the Pwned Passwords range API before acceptance. Refuses any password whose SHA-1 appears in the breach corpus. Fails-open on transport errors. `internal/crypto/hibp.go`
- **Temporary passwords** — admin-created users get a 16-char password from a base58-minus-ambiguous alphabet (~93 bits entropy). Plaintext exists only in the HTTP response; never stored, logged, cached, or written to audit rows. `force_password_change=true` ensures rotation on first sign-in. `internal/crypto/password.go`

## Authentication

- **Opaque session tokens** — 32 bytes from `crypto/rand`, base64url-encoded, stored only in Valkey under `session:<token>`. No JWTs for admin sessions, no client-side claims to forge. `internal/session/`, `internal/auth/handler.go`
- **HttpOnly + SameSite cookies** — admin session cookie is `SameSite=Lax` (deliberately — `/authorize` is the top-level cross-site redirect target for OIDC RPs). MFA transient cookies (`schlass_mfa_challenge`, `schlass_mfa_enroll`) are `SameSite=Strict` — never cross-site. `Secure` is auto-toggled by the `SCHLASS_PUBLIC_URL` scheme. `internal/auth/handler.go`, `internal/session/`
- **Per-request user re-fetch** — the auth middleware re-reads the user row from Postgres on every authed request rather than denormalizing role/status into the session. A user disabled mid-session is revoked in-middleware on the next request. `internal/auth/middleware.go`
- **Session rotation on password change** — `POST /api/change-password` issues a fresh session token after the update commits, invalidating the old one (OWASP Session Management). `internal/auth/handler.go`
- **Global revoke_before cutoff** — "invalidate all sessions" paths (admin disable, admin reset-password, admin reset-mfa, self change-password, self disable-MFA) write a `user:revoke_before:<id>` key in Valkey post-commit. Both the admin auth middleware and the OIDC bearer middleware reject tokens whose `iat` precedes the cutoff. `internal/session/`, `internal/authserver/bearer_middleware.go`
- **Client-level revoke_before cutoff** — hard-deleting an OIDC client writes `client:revoke_before:<id>`; active bearer + refresh tokens for that client are rejected immediately. `internal/session/`, `internal/clients/handler.go`

## Multi-factor authentication (TOTP)

- **Forced enrollment gate** — when `mfa_required=true` and a user is not enrolled, `POST /api/login` issues a `schlass_mfa_enroll` cookie (10-minute TTL) and responds `MFA_ENROLLMENT_REQUIRED`. No session cookie exists until `/api/mfa/enrollment/complete` commits. `internal/auth/handler.go`, `internal/auth/mfa.go`
- **Enrollment transient state in Valkey** — the 3-step wizard stores `user_id`, `secret_base32`, `verify_attempts`, and `recovery_hashes` as a Valkey hash keyed by the enroll token. Nothing reaches Postgres until `/complete`. Abandoned wizards leave no partial state. `internal/auth/mfa.go`
- **Enrollment-complete audit-in-tx** — `/api/mfa/enrollment/complete` runs a single Postgres transaction: `SetTOTPEnrolled` (encrypted secret + `totp_enrolled_at`), `RecoveryCodeStore.Insert` (10 hashes), `mfa.enrollment_completed` audit row. Valkey state is cleared only post-commit. "State written, no audit" is structurally impossible. `internal/auth/mfa.go`
- **TOTP replay prevention** — `users.last_used_totp_counter` stores the step index of the last successful code. `ValidateTOTP` rejects any step ≤ last-counter within the ±1 skew window, so a code cannot authenticate twice in its 30-second window. `internal/crypto/totp.go`, `internal/users/store.go`
- **Challenge attempt cap** — after 5 failed TOTP or recovery-code attempts the challenge Valkey key is deleted, rendering the token dead. Error code `MFA_CHALLENGE_MAX_ATTEMPTS`. `internal/auth/mfa.go`
- **Per-IP challenge rate limit** — default 5 requests per minute per IP on `POST /api/mfa/challenge`, independent of the login limiter. Operator-tunable via `SCHLASS_MFA_CHALLENGE_RATE_LIMIT`. `internal/middleware/ratelimit.go`, `internal/server/router.go`
- **Recovery code constant-time verification** — `verifyRecoveryCode` iterates all unused codes and calls `crypto.VerifyPassword` on every one, even after a match. Response time is independent of how many codes remain, preventing timing-based enumeration of remaining-code count. `internal/auth/mfa.go`
- **Recovery code one-time burn** — `RecoveryCodeStore.MarkUsed` uses `UPDATE ... WHERE id = $1 AND used_at IS NULL RETURNING` and errors if no row was updated. Burn + `login.succeeded` + `mfa.challenge_succeeded` + `mfa.recovery_code_used` audit rows commit in a single transaction. `internal/auth/recovery_code_store.go`, `internal/auth/mfa.go`
- **Admin MFA reset** — `POST /api/users/{id}/reset-mfa` clears `totp_secret_encrypted`, `totp_enrolled_at`, `last_used_totp_counter` and deletes all recovery codes in one transaction with a `mfa.reset` audit row. Next login hits the enrollment flow (if `mfa_required=true`). `internal/users/handler.go`
- **Self-service MFA disable** — `POST /api/me/mfa/disable` with password re-auth clears TOTP state, revokes all sessions, and forces next login through enrollment. The re-auth requirement is the proof-of-possession gate. `internal/auth/handler.go`

## Login surface hardening

- **Per-IP login rate limit** — default 5 requests per minute per IP on `POST /api/login` via Valkey-backed sliding window. Operator-tunable via `SCHLASS_LOGIN_RATE_LIMIT`. `internal/middleware/ratelimit.go`, `internal/config/env.go`
- **Account lockout** — `users.failed_login_attempts` + `users.locked_until` with a concurrent-safe `UPDATE ... WHERE (locked_until IS NULL OR locked_until < now()) RETURNING ...` in both increment and reset paths; the reset refuses to clear an active lock. Threshold (default 5) and duration (default 900 s = 15 min) are read from `instance_config` on every login — admin-tunable via `/admin/settings` (Security tab). `internal/users/store.go`, `internal/auth/handler.go`
- **Enumeration defense (dummy-hash timing equalization)** — `auth.NewHandler` precomputes a dummy Argon2id hash; the user-not-found path runs `VerifyPassword` against it so the cryptographic cost matches the real path. Known imperfection: the post-hash pipeline (lockout UPDATE + richer audit row) still differs by a few milliseconds. `internal/auth/handler.go`

## Password reset

- **Enumeration-safe `POST /api/password-reset/request`** — always returns 200 with an empty body regardless of whether the email exists; dummy-Argon2id keeps timing parity. `internal/auth/password_reset.go`
- **Token construction** — 32-byte `crypto/rand` plaintext, base64url; stored as `HMAC-SHA256(pepper, plaintext)` under a 30-minute single-use TTL. Plaintext lives only in the emailed URL. `internal/auth/password_reset_token_store.go`
- **Rate limit** — default 5 requests/minute per IP on `/request`; operator-tunable via `SCHLASS_PASSWORD_RESET_RATE_LIMIT`. No rate limit on `/confirm` — token possession is proof of auth.
- **Confirm path** — validates under `SELECT ... FOR UPDATE`, hashes the new password, marks the token used, audits `password_reset.completed`, bumps `revoke_before` post-commit. Not-found / expired / already-used all map to a single `INVALID_TOKEN` error code. `internal/auth/password_reset.go`
- **super_admin email-reset blocked** — ENISA NIS2 (Jun-2025) mandates phishing-resistant MFA for privileged accounts, and email reset links are phishable. `POST /api/password-reset/request` refuses to issue for super_admin users (routes them through the unmatched path, no mint, 200), writes a separate `password_reset.admin_blocked` audit. Recovery path is another super_admin via `POST /api/users/:id/reset-password`, or the operator CLI documented in `docs/operator/recovery.md`. `internal/auth/password_reset.go`, `internal/recovery/reset.go`
- **Nightly sweeper** — `internal/server/sweeper.go` deletes `password_reset_tokens expires_at < now() - 30d` and `authorization_codes expires_at < now() - 7d` in one transaction, writes `password_reset.cleanup_swept`. Disable via `SCHLASS_SWEEPER_INTERVAL_SECS=0`.

## OIDC / OAuth 2.1

- **OAuth 2.1 mandatory controls** — PKCE S256 required on every authorization_code flow (including confidential clients); `state` required; exact-match `redirect_uri`; access tokens `typ=at+jwt`; ID tokens `typ=JWT`; `alg=none` and alg-confusion rejected. `internal/authserver/authorize.go`, `internal/authserver/token.go`
- **Signing keys** — RSA-2048 in `signing_keys` table with lifecycle `active → retiring → retired`. Active + retiring keys served in JWKS; retired not. Private keys AES-256-GCM-wrapped. Bootstrap mints the first key if none exist. `internal/signingkeys/`
- **Rotate-on-every-use refresh** — per-family rotation; each use deletes the presented refresh token and inserts a fresh one in the same family. Replay detected → `oidc.refresh.reuse_detected` audit + revoke entire family + 400 `invalid_grant`. Absolute expiry preserved across rotations. `internal/oidc/refresh_store.go`
- **Scope + grant re-validation at `/token`** — every `authorization_code` and `refresh_token` exchange re-intersects the token's scopes against the client's current `allowed_scopes` and re-checks that the grant type is still in `allowed_grant_types`. Admin PATCH narrows take effect immediately. `internal/authserver/token.go`
- **Code-exchange failure audit** — every `handleAuthorizationCode` failure branch that burns the code via `ConsumeOnce` writes a dedicated audit row in the same transaction (`oidc.code.client_mismatch`, `redirect_mismatch`, `pkce_mismatch`, `user_not_found`, `grant_removed`, `scope_removed`, `user_disabled`). A code is never destroyed without a forensic trail. `internal/authserver/token.go`
- **Client secret rotation overlap** — `POST /api/clients/:id/rotate-secret` mints a 32-byte secret, moves the previous hash to `secret_hash_previous` with a 24h overlap; `VerifySecret` tries current-then-previous during the window. Second rotation discards the previous. `internal/clients/handler.go`
- **Hard-delete safety** — migration drops the FK from `audit_logs.client_id` and adds `ON DELETE CASCADE` to `authorization_codes.client_id`, so a client delete is atomic and historical audit rows survive. Post-commit Valkey `client:revoke_before` invalidates outstanding bearer + refresh tokens. `internal/clients/handler.go`
- **return_to whitelist** — three carriers (MFA Valkey hashes, `Session.PendingReturnTo`, terminal JSON `redirect_to`) all re-validate via `oidc.SanitizeReturnTo`: scheme+host must match `SCHLASS_PUBLIC_URL`, path must equal `/authorize`. Fails closed. `internal/oidc/returnto.go`

## Authorization

- **Permission-string middleware** — `users.RequirePermission("<resource>.<action>")` wraps every protected route, returning 403 `FORBIDDEN` for users whose role does not grant the permission. v1 hardcodes `super_admin` → all 10 `users.*` + 8 `clients.*` + `signing_keys.rotate`; `user` → none. Handler-side permission strings do not change when the role-permissions map moves to the DB in v2. `internal/users/permission.go`
- **Role-aware client-side routing** — `<AdminGuard>` in `web/src/App.tsx` redirects non-super_admin users from `/admin/*` before the admin shell renders. `<AuthGuard>` enforces authentication separately. Role-string checks in the frontend are reserved for display (`<RoleBadge>`, admin-count metrics).
- **Self-operation guard** — `rejectSelfOp` is the first check in disable / delete / role-demote handlers, blocking an admin from locking themselves out one operation at a time. `internal/users/handler.go`
- **Last-admin lockout protection** — `lockSuperAdminsForUpdate` takes a row-level lock on every super_admin row to serialize concurrent destructive operations; `enforceLastAdminLockout` counts remaining active super_admins in the same transaction and aborts if the count would reach zero. `internal/users/handler.go`

## Audit logging and tamper protection

- **Audit-in-transaction rule** — every state-changing operation writes an `audit_logs` row inside the same Postgres transaction as the state change. "State change with no audit" is impossible on any documented path. Three deliberate exceptions use best-effort audit instead: the middleware session-revoke path (forcing a logout for an orphan user during a PG blip would cascade to all authed users), the MFA challenge-failed path (the atomic Valkey `HIncrBy -1` decrement is the brute-force guard; the audit row is forensic), and the `revoke_before` enforcement path on the OIDC reject side. `internal/audit/store.go`
- **Append-only at the database level** — RLS enabled with only SELECT + INSERT policies; UPDATE and DELETE revoked from PUBLIC; `schlass_app` granted SELECT + INSERT only. The sole sanctioned mutation is `audit_log_pseudonymize_user(UUID)` — a `SECURITY DEFINER` function owned by `schlass_migrations` that replaces `actor_email` with `deleted:<uuid>` on GDPR Art. 17 erasure. `schlass_app` has EXECUTE only. `internal/database/migrations/000001_baseline.up.sql`
- **Denormalized actor email** — `audit_logs.actor_email` is captured at write time and the FK on `actor_id` is absent, so the audit trail survives user deletion. Joining-when-present still works for non-deleted rows.
- **Correlation ID in audit rows** — every request gets a UUIDv4 injected by `internal/middleware/correlation.go`; the ID lands in `audit_logs.metadata.correlation_id` via the audit store's context-read and in every `slog` access-log line, so forensic investigation pivots between audit trail and access log on a single ID. `internal/middleware/correlation.go`, `internal/audit/store.go`
- **Config-change audit** — every `PATCH /api/settings/:domain` handler emits one audit row per changed field in the same transaction as the write. `smtp_password` metadata is `{"changed": true}` only — never leaks plaintext or ciphertext. `internal/settings/handler.go`

## Database isolation

- **Two-role split** — `schlass_migrations` owns DDL (used only at startup); `schlass_app` runs with the minimum privileges needed to serve traffic. Defends against migration-time mistakes and runtime SQL-injection blast radius. `internal/database/migrations/000001_baseline.up.sql`, `scripts/init-db.sh`
- **Row-level security** — RLS is enabled on `audit_logs` with policies owned by the migrations role, restricting the append-only invariant. `internal/database/migrations/000001_baseline.up.sql`

## HTTP hardening

- **Security headers** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy on every response. `internal/middleware/security_headers.go`
- **Structured request logging** — JSON `slog` on every request: method, path, status, duration, client IP, correlation ID. No text mode in any environment. `internal/middleware/logging.go`

## Data hygiene

- **Email canonicalization** — emails lowercased at the handler boundary before any store call (`internal/server/setup.go`, `internal/users/handler.go`, `internal/auth/handler.go`). The database enforces the canonicalization with a functional unique index `UNIQUE INDEX users_email_lower_key ON users(LOWER(email))`, so a direct SQL insert that bypasses the handler fails loudly instead of creating a phantom duplicate. Defends against user-identity duplication and authentication bypass via case variation. `internal/database/migrations/000001_baseline.up.sql`

## Runtime-configurable policy

These values ship with defaults and are enforced on every request by reading from `instance_config`. Admins mutate them via `/admin/settings` (Security + Tokens tabs); every change emits a `config.<key>.changed` audit row in the same transaction as the write.

- `mfa_required` (bool, default `true`) — when true and a user is not enrolled, login short-circuits to enrollment; when false, enrolled users still pass the challenge but un-enrolled users skip it.
- `password_min_length` (int, default `12`) — minimum password length. Read on every password write (setup, change, reset, admin-create).
- `password_require_upper` (bool, default `true`) — require at least one uppercase letter.
- `password_require_digit` (bool, default `true`) — require at least one digit.
- `lockout_threshold` (int, default `5`) — failed-login attempts before `locked_until` is set.
- `lockout_duration_secs` (int, default `900`, 15 min) — lockout window length.

Every user-supplied password additionally passes the HIBP breach-corpus check regardless of the policy settings. `internal/validate/password.go`, `internal/crypto/hibp.go`

### Env-tunable rate limits

All of these default to 5 requests per minute per IP; set any to an integer > 0 to override, `0` to restore default:

- `SCHLASS_LOGIN_RATE_LIMIT` — `POST /api/login`
- `SCHLASS_MFA_CHALLENGE_RATE_LIMIT` — `POST /api/mfa/challenge`
- `SCHLASS_PASSWORD_RESET_RATE_LIMIT` — `POST /api/password-reset/request`
- `SCHLASS_AUTHORIZE_RATE_LIMIT` — `GET /authorize`
- `SCHLASS_USERINFO_RATE_LIMIT` — `GET /userinfo`
- `SCHLASS_TOKEN_RATE_LIMIT` — `POST /token` (per-client, not per-IP)

Sweeper interval (expired-token cleanup) is env-tunable via `SCHLASS_SWEEPER_INTERVAL_SECS` (default `86400` = 24 h; `0` disables).

## Known limitations

- **Admin-UI token-TTL edits are silent no-ops.** The Tokens tab at `/admin/settings` accepts `access_token_ttl_secs` and `refresh_token_ttl_secs` changes, writes them to `instance_config`, and emits a `config.<key>.changed` audit row — but the signing path reads the Go constants `oidc.AccessTokenTTL` (15 min) and `authserver/token.go:refreshTokenTTL` (24 h) directly. The stored values are displayed, not enforced. Wiring the authserver to `instance_config` is pending work. `internal/oidc/claims.go`, `internal/authserver/token.go`
- **Post-hash timing parity is imperfect.** The pipeline after `VerifyPassword` diverges by a few milliseconds between known-wrong-password and unknown-user (extra UPDATE on the real path). Acceptable at the current scale; will be revisited when the multi-user surface widens.
- **No step-up re-authentication at enrollment completion.** The `schlass_mfa_enroll` cookie grants the ability to finish TOTP setup for the associated user. An attacker with `SameSite=Strict` + `HttpOnly` bypass (malware on the user's machine, physical access) could complete enrollment with their own authenticator within the 10-minute window. Mitigations: strict cookie attributes, the user physically holds the authenticator during setup, and the super_admin email-reset block closes the highest-risk phishing vector.
- **`refresh_token` auth-grant failures use best-effort audit**, not audit-in-tx. Documented exception — the refresh store mutation is Valkey-backed, not SQL; wrapping it in a PG tx would not make the audit atomic with the rotation.
- **KEK rotation tooling is not yet shipped.** The envelope format allows a DEK rewrap under a new KEK without touching plaintext, but no CLI exists. Rotate by staging a new deploy with a writable-by-both-keys wrapper — future work.
- **Single-instance only.** No support for horizontal scaling: session state is in Valkey (fine for one node), signing keys are shared via Postgres, but there is no leader election for the sweeper or the retire-sweep. Running multiple replicas causes double-audit rows from concurrent sweep ticks.
