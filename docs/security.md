# Security Measures

Each entry names a control, what it defends, and the file(s) implementing it. Paths are relative to the repo root.

## Cryptography

- **Password hashing (Argon2id)** — Argon2id at 19 MiB, 2 iterations, parallelism 1, with per-password random salt and PHC-encoded output. Defends against offline cracking of stolen hashes. `internal/crypto/password.go`
- **Encryption at rest for sensitive config** — AES-256-GCM with a 32-byte key from `SCHLASS_ENCRYPTION_KEY`, used for `smtp_password` and `totp_secret` rows in `instance_config`. Defends against database-dump disclosure of secrets. `internal/crypto/encryption.go`, `internal/config/config_service.go`

## Authentication

- **Opaque session tokens** — 32 bytes from `crypto/rand`, base64url-encoded, stored only in Valkey under `session:<token>`. No JWTs, no client-side claims to forge. `internal/session/`, `internal/handler/auth.go`
- **HttpOnly + SameSite=Strict cookies** — `Secure` is auto-toggled by the `SCHLASS_PUBLIC_URL` scheme at handler construction. Defends against XSS exfiltration and cross-site request forgery via session cookie. `internal/handler/auth.go`
- **Per-request user re-fetch** — auth middleware re-reads the user row from Postgres on every authed request rather than denormalizing role/status into the session. Disabled users are revoked in-middleware. `internal/middleware/auth.go`
- **Session rotation on password change** — `POST /api/change-password` issues a new session token after the password update commits, invalidating the old one (OWASP Session Management). `internal/handler/auth.go`

## Login surface hardening

- **Per-IP login rate limit** — 5 requests per minute per IP on `POST /api/login` via Valkey-backed sliding window. Defends against credential-stuffing bursts. `internal/middleware/ratelimit.go`, `internal/server/router.go`
- **Account lockout (failed-attempt counter)** — `users.failed_login_attempts` + `users.locked_until` with a concurrent-safe `UPDATE ... WHERE (locked_until IS NULL OR locked_until < now()) RETURNING ...` pattern in both increment and reset paths; the reset refuses to clear an active lock. `internal/store/user_store.go`, `internal/handler/auth.go`
- **Enumeration defense (dummy-hash timing equalization)** — `NewAuthHandler` precomputes a dummy Argon2id hash; the user-not-found path runs `VerifyPassword` against it so the cryptographic cost matches the real-user path. Imperfection: the post-hash pipeline (lockout UPDATE + richer audit row) still differs by a few milliseconds — see CLAUDE.md "Known limitation — enumeration timing parity is imperfect". `internal/handler/auth.go`

## Authorization

- **Role-gate middleware** — `RequireRole("super_admin")` wraps every `/api/users/*` route after `Auth`, returning 403 `FORBIDDEN` for non-super-admins. `internal/middleware/role.go`, `internal/server/router.go`
- **Self-operation guard** — `rejectSelfOp` is the first check in disable, delete, and role-demote handlers, blocking an admin from locking themselves out one operation at a time. `internal/handler/users.go`
- **Last-admin lockout protection** — `lockSuperAdminsForUpdate` takes a row-level lock on every super_admin row to serialize concurrent destructive operations; `enforceLastAdminLockout` then counts remaining active super_admins inside the same transaction and aborts if the count would reach zero. `internal/handler/users.go`

## Audit logging and tamper protection

- **Audit-in-transaction rule** — login success/failure, logout, setup, and every Sprint 3 user-management mutation write their `audit_logs` row inside the same Postgres transaction as the state change, so "state change with no audit" is impossible. See CLAUDE.md "Audit-in-tx rule" for the full property statement. `internal/handler/auth.go`, `internal/handler/setup.go`, `internal/handler/users.go`
- **Append-only audit log at the database level** — RLS enabled with only SELECT and INSERT policies; UPDATE and DELETE revoked from PUBLIC; `schlass_app` granted only SELECT + INSERT. This is a load-bearing compliance claim. `internal/database/migrations/000007_create_audit_logs.up.sql`, `internal/database/migrations/000010_grant_app_privileges.up.sql`
- **Denormalized actor email** — `audit_logs.actor_email` is stored at write time and the `actor_id` foreign key was dropped in migration 11, so the audit trail survives user deletion. `internal/database/migrations/000011_drop_audit_actor_fk.up.sql`, `internal/store/audit_store.go`

## Database isolation

- **Two-role split** — `schlass_migrations` owns DDL (used only at startup); `schlass_app` is the runtime role with the minimum privileges needed to serve traffic. Defends against migration-time mistakes and runtime SQL-injection blast radius. `internal/database/migrations/000010_grant_app_privileges.up.sql`, `scripts/init-db.sh`
- **Row-level security** — RLS is enabled on `audit_logs` (and other sensitive tables) and policies are owned by the migrations role. `internal/database/migrations/000007_create_audit_logs.up.sql`, `internal/database/migrations/000010_grant_app_privileges.up.sql`

## HTTP hardening

- **Security headers middleware** — sets HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy on every response. `internal/middleware/security_headers.go`
- **Structured request logging** — JSON `slog` on every request with method, path, status, duration, and client IP; no text mode in any environment so dev and prod log the same shape. `internal/middleware/logging.go`

## Defaults

- **MFA required by default** — new instances ship with `mfa_required = true` in `instance_config`. `internal/config/config_service.go`
- **Password policy** — minimum 12 characters, at least one uppercase letter, at least one digit, enforced on every password write path. `internal/model/validation.go`
