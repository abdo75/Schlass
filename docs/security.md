# Security Measures

Each entry names a control, what it defends, and the file(s) implementing it. Paths are relative to the repo root.

## Cryptography

- **Password hashing (Argon2id)** — Argon2id at 19 MiB, 2 iterations, parallelism 1, with per-password random salt and PHC-encoded output. Defends against offline cracking of stolen hashes. `internal/crypto/password.go`
- **Encryption at rest for sensitive config** — AES-256-GCM with a 32-byte key from `SCHLASS_ENCRYPTION_KEY`, used for `smtp_password` and per-user `totp_secret_encrypted` columns. Defends against database-dump disclosure of secrets. `internal/crypto/encryption.go`, `internal/config/config_service.go`
- **TOTP secret generation** — 160-bit secret (20 random bytes from `crypto/rand`), base32-encoded without padding per RFC 6238. Algorithm: SHA1, 6 digits, 30-second period. Stored AES-256-GCM encrypted in `users.totp_secret_encrypted`; decrypted only at challenge time. `internal/crypto/totp.go`
- **Recovery code generation** — 10 single-use codes per enrollment, format `XXXX-XXXX` from a 57-character base58-minus-ambiguous alphabet (~46 bits per code). Hashed with Argon2id (same policy as passwords); plaintext returned once and never stored. `internal/crypto/recovery_codes.go`

## Temporary password generation

Admins never type passwords when creating or resetting users. The server generates a 16-character password from a base58-minus-ambiguous alphabet (~93 bits entropy) via `crypto/rand`. The plaintext exists only in the HTTP response; it is never stored, logged, cached, or written to audit rows. `force_password_change=true` ensures the user rotates it on first sign-in. Implementation: `internal/crypto/password.go:GenerateTemporaryPassword`.

## Authentication

- **Opaque session tokens** — 32 bytes from `crypto/rand`, base64url-encoded, stored only in Valkey under `session:<token>`. No JWTs, no client-side claims to forge. `internal/session/`, `internal/handler/auth.go`
- **HttpOnly + SameSite=Strict cookies** — `Secure` is auto-toggled by the `SCHLASS_PUBLIC_URL` scheme at handler construction. Defends against XSS exfiltration and cross-site request forgery via session cookie. `internal/handler/auth.go`
- **Per-request user re-fetch** — auth middleware re-reads the user row from Postgres on every authed request rather than denormalizing role/status into the session. Disabled users are revoked in-middleware. `internal/middleware/auth.go`
- **Session rotation on password change** — `POST /api/change-password` issues a new session token after the password update commits, invalidating the old one (OWASP Session Management). `internal/handler/auth.go`

## Multi-factor authentication (TOTP)

- **Forced enrollment gate** — when `mfa_required = true` and a user is not yet enrolled, `POST /api/login` issues a `schlass_mfa_enroll` cookie (10-minute TTL) and responds `MFA_ENROLLMENT_REQUIRED` instead of creating a session. The enrollment wizard consumes this cookie; no session exists until `/api/mfa/enrollment/complete` commits successfully. `internal/handler/auth.go`, `internal/handler/mfa.go`
- **Enrollment transient state in Valkey** — the 3-step wizard stores `user_id`, `secret_base32`, `verify_attempts`, and `recovery_hashes` as a Valkey hash keyed by the enroll token. The hash never reaches PG until `/complete`. If the wizard is abandoned or the TTL expires, no partial MFA state is persisted. `internal/handler/mfa.go`
- **Enrollment-complete audit-in-tx** — `/api/mfa/enrollment/complete` performs a single PG transaction: `SetTOTPEnrolled` (writes encrypted secret, sets `totp_enrolled_at`), `RecoveryCodeStore.Insert` (10 hashes), and a `mfa.enrollment_completed` audit row. The Valkey enrollment key is deleted only after the tx commits, ensuring "state written, no audit" is structurally impossible. `internal/handler/mfa.go`
- **TOTP replay prevention** — `users.last_used_totp_counter` stores the step index (unix/30) of the last successful code. `ValidateTOTP` checks each step in the ±1 skew window against `lastCounter`; a step ≤ lastCounter is rejected unconditionally, preventing the same code from authenticating twice within its 30-second window. `internal/crypto/totp.go`, `internal/store/user_store.go`
- **Challenge transient state in Valkey** — `POST /api/login` for an enrolled user issues a `schlass_mfa_challenge` cookie (120-second TTL), writing `user_id` and `attempts_remaining=5` to a Valkey hash. The challenge handler atomically decrements `attempts_remaining` before any verification work, preventing concurrent races on the attempt counter. `internal/handler/auth.go`, `internal/handler/mfa.go`
- **Challenge attempt cap** — after 5 failed TOTP or recovery-code attempts (`attempts_remaining` hits -1), the challenge Valkey key is deleted, rendering the token dead. The client must start a new login. Error code: `MFA_CHALLENGE_MAX_ATTEMPTS`. `internal/handler/mfa.go`
- **Per-IP MFA challenge rate limit** — 5 requests per minute per IP on `POST /api/mfa/challenge`, independent of the login rate limiter. Overridable via `SCHLASS_MFA_CHALLENGE_RATE_LIMIT` for high-traffic or test environments. `internal/middleware/ratelimit.go`, `internal/server/router.go`
- **Recovery code constant-time verification** — `verifyRecoveryCode` always iterates all 10 unused codes and calls `crypto.VerifyPassword` for every one, even after finding a match. This ensures the response time is independent of how many codes remain (constant ~10× Argon2id cost), preventing timing-based enumeration of remaining-code count. `internal/handler/mfa.go`
- **Recovery code one-time burn** — `RecoveryCodeStore.MarkUsed` uses `UPDATE ... WHERE id = $1 AND used_at IS NULL` and returns an error if no row was updated (code already burned or doesn't exist). The burn, `login.succeeded`, `mfa.challenge_succeeded`, and `mfa.recovery_code_used` audit rows are committed in a single transaction. `internal/store/recovery_code_store.go`, `internal/handler/mfa.go`
- **Admin MFA reset** — `POST /api/users/{id}/reset-mfa` clears `totp_secret_encrypted`, `totp_enrolled_at`, `last_used_totp_counter` on the user row and deletes all recovery codes in a single tx with a `mfa.reset` audit row. After reset, the user is forced through enrollment again on next login (if `mfa_required = true`). `internal/handler/users.go`
- **Challenge failed audit (best-effort)** — `mfa.challenge_failed` audit rows use a separate short-lived tx (not the decrement tx), logged ERROR-level on failure but never blocking the HTTP response. This is a documented exception to the audit-in-tx rule: the decrement is the atomic brute-force guard; the audit row is forensic, not the control plane. See CLAUDE.md "Documented exception" pattern. `internal/handler/mfa.go`

### Known v1 limitations

- **Self-service MFA disable shipped** (was previously out of scope per v1-scope). Users can disable their own TOTP via `POST /api/me/mfa/disable` with password re-auth; all sessions are revoked on success, next login hits enrollment. Admin-only MFA *recovery* (user has lost their authenticator) remains admin-gated — the two scenarios have different threat models: disable requires the user to prove possession via password, recovery cannot and requires a trusted third party.
- **No step-up re-authentication at enrollment completion.** The enrollment-token cookie (`schlass_mfa_enroll`) grants the ability to finish TOTP setup for the associated user. An attacker who steals this cookie (malware on the user's machine, physical access) could complete enrollment with their own authenticator. Mitigations in place: `SameSite=Strict` + `HttpOnly` prevent cross-site theft; 10-minute TTL limits the window; the user physically holds the authenticator during setup. **Gold-standard defence would require the user to re-enter their password at `POST /api/mfa/enrollment/complete`** — not in v1, deferred to Sprint 6 alongside the forgot-password flow where a similar proof-of-possession step lands. v1's threat model is the SME with trusted company devices, not consumer-grade attack surface.
- **No session binding on enrollment tokens.** Since enrollment happens before a session exists (the very first login for a mandatory-MFA instance), the enrollment cookie cannot be bound to a session token. v2 could introduce a pre-session signed token (like PKCE's `code_verifier`) but the implementation cost exceeds the marginal security gain at the v1 threat level.

## Login surface hardening

- **Per-IP login rate limit** — 5 requests per minute per IP on `POST /api/login` via Valkey-backed sliding window. Defends against credential-stuffing bursts. `internal/middleware/ratelimit.go`, `internal/server/router.go`
- **Account lockout (failed-attempt counter)** — `users.failed_login_attempts` + `users.locked_until` with a concurrent-safe `UPDATE ... WHERE (locked_until IS NULL OR locked_until < now()) RETURNING ...` pattern in both increment and reset paths; the reset refuses to clear an active lock. `internal/store/user_store.go`, `internal/handler/auth.go`
- **Enumeration defense (dummy-hash timing equalization)** — `NewAuthHandler` precomputes a dummy Argon2id hash; the user-not-found path runs `VerifyPassword` against it so the cryptographic cost matches the real-user path. Imperfection: the post-hash pipeline (lockout UPDATE + richer audit row) still differs by a few milliseconds — see CLAUDE.md "Known limitation — enumeration timing parity is imperfect". `internal/handler/auth.go`

## Authorization

- **Permission-gate middleware** — `RequirePermission("<resource>.<action>")` wraps every protected route after `Auth`, returning 403 `FORBIDDEN` for users whose role does not grant the permission. V1 hardcodes `super_admin` → all 10 `users.*` permissions and `user` → none in `internal/middleware/permission.go`; v2 will replace the in-process map with a `roles` / `role_permissions` DB lookup. Handler-side permission strings do not change across that migration. `internal/middleware/permission.go`, `internal/server/router.go`
- **Role-aware SPA routing** — `<AdminGuard>` in `web/src/components/AdminGuard.tsx` redirects non-super_admin users from `/admin/*` to `/account` before the admin shell renders. Complements `<AuthGuard>` (which only checks authentication). `LoginPage` and `ChangePasswordForm` branch post-auth navigation on `user.role` so a `role=user` never lands on a route they cannot use. `web/src/components/AdminGuard.tsx`, `web/src/features/auth/LoginPage.tsx`, `web/src/features/auth/ChangePasswordForm.tsx`, `web/src/App.tsx`
- **Self-operation guard** — `rejectSelfOp` is the first check in disable, delete, and role-demote handlers, blocking an admin from locking themselves out one operation at a time. `internal/handler/users.go`
- **Last-admin lockout protection** — `lockSuperAdminsForUpdate` takes a row-level lock on every super_admin row to serialize concurrent destructive operations; `enforceLastAdminLockout` then counts remaining active super_admins inside the same transaction and aborts if the count would reach zero. `internal/handler/users.go`

## Audit logging and tamper protection

- **Audit-in-transaction rule** — login success/failure, logout, setup, and every Sprint 3 user-management mutation write their `audit_logs` row inside the same Postgres transaction as the state change, so "state change with no audit" is impossible. See CLAUDE.md "Audit-in-tx rule" for the full property statement. `internal/handler/auth.go`, `internal/handler/setup.go`, `internal/handler/users.go`
- **Append-only audit log at the database level** — RLS enabled with only SELECT and INSERT policies; UPDATE and DELETE revoked from PUBLIC; `schlass_app` granted only SELECT + INSERT. This is a load-bearing compliance claim. `internal/database/migrations/000007_create_audit_logs.up.sql`, `internal/database/migrations/000010_grant_app_privileges.up.sql`
- **Denormalized actor email** — `audit_logs.actor_email` is stored at write time and the `actor_id` foreign key was dropped in migration 11, so the audit trail survives user deletion. `internal/database/migrations/000011_drop_audit_actor_fk.up.sql`, `internal/store/audit_store.go`
- **Correlation ID in audit rows** — every audit row's `metadata.correlation_id` carries the UUIDv4 injected by `middleware.RequestLogging` into the request context (stored via `internal/requestcontext/correlation.go`). The same ID appears in the structured access log (`slog` attribute `correlation_id`), so forensic investigation can pivot between audit trail and access log with a single ID lookup. `internal/requestcontext/correlation.go`, `internal/middleware/logging.go`, `internal/store/audit_store.go`

## Database isolation

- **Two-role split** — `schlass_migrations` owns DDL (used only at startup); `schlass_app` is the runtime role with the minimum privileges needed to serve traffic. Defends against migration-time mistakes and runtime SQL-injection blast radius. `internal/database/migrations/000010_grant_app_privileges.up.sql`, `scripts/init-db.sh`
- **Row-level security** — RLS is enabled on `audit_logs` (and other sensitive tables) and policies are owned by the migrations role. `internal/database/migrations/000007_create_audit_logs.up.sql`, `internal/database/migrations/000010_grant_app_privileges.up.sql`

## HTTP hardening

- **Security headers middleware** — sets HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy on every response. `internal/middleware/security_headers.go`
- **Structured request logging** — JSON `slog` on every request with method, path, status, duration, and client IP; no text mode in any environment so dev and prod log the same shape. `internal/middleware/logging.go`

## Data hygiene

- **Email canonicalization** — emails are lowercased at the handler boundary before any store call (`internal/handler/setup.go`, `internal/handler/users.go` Create/Update, `internal/handler/auth.go` PostLogin). The database enforces the canonicalization with a functional unique index `UNIQUE INDEX users_email_lower_key ON users(LOWER(email))` (migration 000012), so a direct SQL insert that bypasses the handler still fails loudly instead of creating a phantom duplicate. Defends against user-identity duplication and against authentication bypass via case variation.

## Defaults

- **MFA required by default** — new instances ship with `mfa_required = true` in `instance_config`. `internal/config/config_service.go`
- **Password policy** — minimum 12 characters, at least one uppercase letter, at least one digit, enforced on every password write path. `internal/model/validation.go`
