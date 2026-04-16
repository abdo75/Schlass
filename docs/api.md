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
