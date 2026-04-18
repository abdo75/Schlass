# API Reference

All routes are wired in `internal/server/router.go`. This doc covers `/api/*` only; the embedded SPA fallback (`mux.Handle("/", web.SPAHandler())`) is intentionally omitted. JSON request and response bodies; session cookie is the auth credential. "Auth" means `middleware.Auth` is required; "Admin" means `RequireRole("super_admin")` is also enforced.

## Health

- `GET /api/health` — liveness + PG/Valkey reachability check (public)

## Setup

First-run wizard. Both routes are rate-limited and become unavailable after `setup_complete = true`.

- `GET /api/setup` — return setup status + current draft config (public, 10/min per IP)
- `POST /api/setup` — finalize first-run setup, create initial super_admin (public, 5/min per IP)

## Authentication

- `POST /api/login` — authenticate, returns session cookie (public, 5/min per IP)
- `POST /api/logout` — destroy current session (Auth)
- `GET /api/me` — return the authenticated user (Auth)
- `POST /api/change-password` — self-service password change, rotates session token (Auth)

## User management

All routes Admin (`super_admin` only). Implemented in `internal/handler/users.go`.

- `GET /api/users` — paginated list with optional search filter
- `POST /api/users` — create a new user (admin provides email and role; server generates a temporary password). Request: `{ email, role }`. Response: `{ user, temporary_password }`.
- `GET /api/users/{id}` — fetch one user
- `PATCH /api/users/{id}` — update mutable fields (email, role, mfa_required)
- `POST /api/users/{id}/disable` — set status to disabled and revoke active sessions
- `POST /api/users/{id}/enable` — restore a disabled user
- `POST /api/users/{id}/reset-password` — issue an admin-initiated password reset; server generates a new temporary password. Response: `{ temporary_password }`.
- `DELETE /api/users/{id}` — hard delete
- `GET /api/users/{id}/sessions` — list active sessions for a user
- `DELETE /api/users/{id}/sessions` — terminate all sessions for a user
- `DELETE /api/users/{id}/sessions/{token}` — terminate a single session by token
- `POST /api/users/{id}/reset-mfa` — admin wipes a user's TOTP secret and all recovery codes (Admin). Request body empty. Response: `{ "ok": true }`.

## MFA enrollment

Enrollment endpoints are gated by the `schlass_mfa_enroll` cookie issued by `POST /api/login` when `mfa_required = true` and the user is not yet enrolled. **No session cookie is present at this stage** — the user is not authenticated until `/complete` succeeds.

- `POST /api/mfa/enrollment/start` — generate a fresh TOTP secret and provision URI. Response: `{ secret_base32, provision_uri }`. Idempotent within the enrollment window: calling again overwrites the secret in Valkey, resetting the 10-minute window.
- `POST /api/mfa/enrollment/verify` — verify the first TOTP code to confirm the user's authenticator is configured. Request: `{ code }`. Response: `{ recovery_codes: [10 plaintext codes] }`. Codes are shown once; hashes are stashed in Valkey for the `/complete` commit. Up to 5 failed attempts before the enrollment session is invalidated.
- `POST /api/mfa/enrollment/complete` — commit enrollment to PG (atomic): writes `totp_secret_encrypted`, inserts 10 recovery-code hashes, writes `mfa.enrollment_completed` audit row. Request: `{ acknowledged: true }`. On success, clears the enroll cookie, creates a regular session cookie, and responds with `{ user }`. This is the audit-in-tx commit point for enrollment.

## MFA challenge

The `schlass_mfa_challenge` cookie is issued by `POST /api/login` when the user is already enrolled. The user must pass the challenge before receiving a session.

- `POST /api/mfa/challenge` — verify a 6-digit TOTP code or a recovery code (public endpoint, 5/min per IP). Request: `{ code }` for TOTP or `{ recovery_code }` for backup. On TOTP success: advances `last_used_totp_counter` (replay prevention), writes `login.succeeded` + `mfa.challenge_succeeded` audit rows, clears challenge cookie, creates session. On recovery code success: additionally writes `mfa.recovery_code_used` and marks the code burned. Up to 5 failed attempts before the challenge session is invalidated. Recovery code verification always iterates all unused codes in constant time (no early exit) to prevent timing-based enumeration of remaining-code count.
