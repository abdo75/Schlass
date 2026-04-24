# Token TTL wiring — config-driven access + refresh token lifetimes

**Date:** 2026-04-24
**Branch:** `fix/token-ttl-wiring`
**Base:** `main @ cc3ab13`
**Author (architect):** Claude
**Implementer:** Codex
**Closes:** `docs/security.md` "Known limitations" bullet on admin-UI token-TTL silent no-op.

> **Handoff note:** Per-file scope review after each file edit — report sufficient / too-much / too-little and trim before moving on. Delete this plan file in the final commit before merge (multi-agent workflow convention).

---

## 1. Context

Admin UI at `/admin/settings/tokens` writes `access_token_ttl_secs` and `refresh_token_ttl_secs` into `instance_config`, emits `config.<key>.changed` audit rows, and the settings snapshot renders the stored values. But the signing path hardcodes three Go constants:

- `internal/oidc/claims.go:11` — `AccessTokenTTL = 15 * time.Minute`
- `internal/oidc/claims.go:12` — `IDTokenTTL = 15 * time.Minute`
- `internal/authserver/token.go:55` — `refreshTokenTTL = 24 * time.Hour`

Result: admin edits are persisted and audited but never enforced. Documented in `docs/security.md` since public-release prep (#33).

## 2. Decision

Read `access_token_ttl_secs` + `refresh_token_ttl_secs` from `instance_config` at token-issuance time via `instanceconfig.Service`. Drop the three constants. ID-token TTL reuses `access_token_ttl_secs` (no new admin field).

### Rejected alternatives

- **Cache TTLs in `TokenHandler` struct with periodic refresh** — invalidation complexity, admin-change lag. Extra DB read per token is cheap (indexed pkey, already inside an open tx on the authcode path).
- **Separate `id_token_ttl_secs` admin field** — no current driver for divergence; Auth0/Keycloak tie ID-token lifetime to access-token lifetime by default.
- **Pass TTLs via constructor only (read once at startup)** — same staleness problem as caching, worse.

## 3. Architecture

### Read paths

| Caller | Querier | Reason |
|--------|---------|--------|
| `handleAuthorizationCode` | open tx (`tx`, line 164) | Tx already covers the whole flow — audit writes already use it. TTL read joins the same tx for consistency. |
| `handleRefreshToken` | `h.pool` | Sign path runs BEFORE tx opens (tx opens line 734 only for audit log). Transactional-grade TTL read is unnecessary; a config snapshot at the top of the sign path is fine. |

### Refresh TTL usage matrix

| Path | Uses refresh TTL? |
|------|-------------------|
| `handleAuthorizationCode` line 404 (new family creation) | **yes** — new refresh token gets `now + refresh_ttl` absolute expiry |
| `handleRefreshToken` line 717 (rotation) | **no** — preserves `oldPayload.Expires` (absolute ceiling from initial exchange) |

This preserves existing semantics. Changing `refresh_token_ttl_secs` in admin UI affects only refresh tokens issued from NEW auth_code exchanges — existing rotating families keep their original 24h ceiling. This is correct: the ceiling is a security property of the family, not a runtime knob.

### Helper signature

```go
// readTokenTTLs returns (access, refresh) durations from instance_config.
// Callers pass the tx when one is open, otherwise h.pool.
// Errors propagate — no silent fallback to a hardcoded default. The
// baseline migration seeds both rows, so "key missing" is a real bug.
func (h *TokenHandler) readTokenTTLs(ctx context.Context, q database.Querier) (access, refresh time.Duration, err error)
```

Returns both even when caller only needs access — trivial overhead, simpler than two helpers.

### Claim builder signatures

```go
// Before:
func BuildAccessClaims(user *users.User, clientID, issuer, jti string, scopes Scopes, now time.Time) AccessTokenClaims
func BuildIDClaims(user *users.User, clientID, issuer, jti, nonce string, scopes Scopes, authTime, now time.Time) IDTokenClaims

// After — append ttl as last param:
func BuildAccessClaims(user *users.User, clientID, issuer, jti string, scopes Scopes, now time.Time, ttl time.Duration) AccessTokenClaims
func BuildIDClaims(user *users.User, clientID, issuer, jti, nonce string, scopes Scopes, authTime, now time.Time, ttl time.Duration) IDTokenClaims
```

`Expires: now.Add(ttl).Unix()` inside each.

### Response body

`tokenResponse.ExpiresIn` now uses `int(access.Seconds())` — the locally-read TTL, not a constant.

## 4. Error handling

`readTokenTTLs` errors → `server_error` (500). No fallback. Rollback the open tx via existing defer (authcode path). Aligns with existing behavior for other infra failures in the handler (signing key lookup, audit write, etc.).

## 5. File manifest

**New:**
- `test/integration/token_ttl_dynamic_test.go`

**Modified:**
- `internal/oidc/claims.go` — drop 2 consts; add `ttl time.Duration` to both builders
- `internal/oidc/claims_test.go` — update call sites + focused TTL-applied assertions
- `internal/authserver/token.go` — drop `refreshTokenTTL` const; add `instanceConfig` field + ctor arg; add `readTokenTTLs` helper; wire into both paths
- `internal/instanceconfig/service.go` — add typed getters `AccessTokenTTLSecs(ctx, q) (int, error)` and `RefreshTokenTTLSecs(ctx, q) (int, error)` (thin wrappers over `s.store.GetInt`)
- `internal/server/router.go` — pass `instanceConfig` into `NewTokenHandler` (around line 196)
- `docs/security.md` — drop "Known limitations" bullet (lines 128-130)

**Deleted (in final pre-merge commit):**
- `docs/plans/token-ttl-wiring.md` (this file)

**Folders:** none added/deleted.

## 6. Implementation steps

### Task 1 — Branch state

- [ ] Confirm `git status --porcelain` is clean OR only contains unrelated pre-existing edits (`docs/operator/recovery.md` may already be modified — leave untouched).
- [ ] Confirm current branch is `fix/token-ttl-wiring` (base `cc3ab13`).

### Task 2 — `internal/instanceconfig/service.go`

- [ ] Add two exported getters:
  ```go
  func (s *Service) AccessTokenTTLSecs(ctx context.Context, q database.Querier) (int, error) {
      return s.store.GetInt(ctx, q, "access_token_ttl_secs")
  }
  func (s *Service) RefreshTokenTTLSecs(ctx context.Context, q database.Querier) (int, error) {
      return s.store.GetInt(ctx, q, "refresh_token_ttl_secs")
  }
  ```
- [ ] Place them next to existing typed getters for consistency. Match the `InstanceName` / `PasswordPolicy` style — no docstring unless the why is non-obvious.

**Per-file scope review.**

### Task 3 — `internal/oidc/claims.go`

- [ ] Delete the `const ( AccessTokenTTL ... IDTokenTTL ... )` block (lines 10-13).
- [ ] Add `ttl time.Duration` as the last param of `BuildAccessClaims`; set `Expires: now.Add(ttl).Unix()`.
- [ ] Add `ttl time.Duration` as the last param of `BuildIDClaims`; set `Expires: now.Add(ttl).Unix()`.
- [ ] Run `grep -rn "AccessTokenTTL\|IDTokenTTL" --include="*.go"` across `internal/`, `test/`, `cmd/` — any remaining hits in production code (NOT `AccessTokenTTLSecs` / `RefreshTokenTTLSecs` field names on the settings structs — those are a separate namespace) must be chased down.

**Per-file scope review.**

### Task 4 — `internal/oidc/claims_test.go`

- [ ] Update every `BuildAccessClaims` call to pass an explicit `ttl` value.
- [ ] Update every `BuildIDClaims` call to pass an explicit `ttl` value.
- [ ] Add one focused test per builder asserting that `Expires - IssuedAt == int64(ttl.Seconds())` for a distinct non-default TTL (e.g. 17 min access, 23 min id — distinct values to guarantee no cross-wiring).
- [ ] `go test ./internal/oidc/...` passes.

**Per-file scope review.**

### Task 5 — `internal/authserver/token.go`

- [ ] Delete `const ( refreshTokenTTL = 24 * time.Hour ... )` block.
- [ ] Add `instanceConfig *instanceconfig.Service` field on `TokenHandler`.
- [ ] Extend `NewTokenHandler` signature — add `instanceConfig *instanceconfig.Service` after `sessionStore session.Store`. Assign in returned struct.
- [ ] Add `readTokenTTLs` helper per the signature in §3.
- [ ] In `handleAuthorizationCode` (right after scope intersection, before signing ~line 351):
  ```go
  accessTTL, refreshTTL, err := h.readTokenTTLs(r.Context(), tx)
  if err != nil {
      slog.Error("token: readTokenTTLs", "error", err)
      writeTokenError(w, http.StatusInternalServerError, "server_error", "Could not read token TTLs.")
      return
  }
  ```
  Then:
  - Pass `accessTTL` into `BuildAccessClaims` + `BuildIDClaims`.
  - Use `refreshTTL` in `refreshStore.Create` → `Expires: now.Add(refreshTTL).Unix()`.
  - Use `int(accessTTL.Seconds())` for `tokenResponse.ExpiresIn`.
- [ ] In `handleRefreshToken` (right before signing ~line 689, just before `now := time.Now().UTC()`):
  ```go
  accessTTL, _, err := h.readTokenTTLs(r.Context(), h.pool)
  if err != nil {
      slog.Error("token refresh: readTokenTTLs", "error", err)
      writeTokenError(w, http.StatusInternalServerError, "server_error", "Could not read token TTLs.")
      return
  }
  ```
  Then:
  - Pass `accessTTL` into `BuildAccessClaims` + `BuildIDClaims`.
  - Use `int(accessTTL.Seconds())` for `tokenResponse.ExpiresIn` at line 770.
  - **Do NOT** touch `refreshStore.Create` in this path — `Expires: oldPayload.Expires` stays (absolute ceiling preservation).
- [ ] `go build ./...` passes clean.
- [ ] `go test ./internal/authserver/... ./internal/oidc/...` passes.

**Per-file scope review.** (Heaviest file in this PR — review carefully. Trim any drift beyond the diff above.)

### Task 6 — `internal/server/router.go`

- [ ] Locate `NewTokenHandler` call (around line 196).
- [ ] Pass the existing `instanceConfig` service instance (already wired elsewhere in router setup for settings handler + mail) as the new arg.
- [ ] `go build ./...` passes.

**Per-file scope review.**

### Task 7 — `test/integration/token_ttl_dynamic_test.go` (new)

- [ ] Pattern off existing integration tests. PATCH flow style from `test/integration/settings_test.go`; auth_code grant flow from whichever existing OIDC integration test is simplest. Use shared helpers — do NOT copy-paste setup.
- [ ] **Case 1 — default TTLs, no PATCH:**
  - Drive auth_code grant.
  - Assert `expires_in == 900`, access JWT `exp - iat == 900`, ID JWT `exp - iat == 900`, refresh row `Expires - CreatedAt == 86400`.
- [ ] **Case 2 — custom TTLs:**
  - PATCH `{access_token_ttl_secs: 600, refresh_token_ttl_secs: 7200}`.
  - Drive a NEW auth_code grant.
  - Assert `expires_in == 600`, access JWT `exp - iat == 600`, ID JWT `exp - iat == 600`, refresh row `Expires - CreatedAt == 7200`.
- [ ] **Case 3 — refresh rotation preserves absolute ceiling:**
  - From Case 2 state, rotate the refresh token.
  - Assert rotated refresh `Expires` == original refresh `Expires` (NOT `now + 7200`). Documents the invariant from `token.go:717`.
- [ ] `go test ./test/integration/... -run TestTokenTTL` passes.

**Per-file scope review.**

### Task 8 — `docs/security.md`

- [ ] Remove the "Known limitations" bullet at lines 128-130 starting with `- **Admin-UI token-TTL edits are silent no-ops.**`.
- [ ] If that was the only bullet in the "Known limitations" section, remove the section header too. Otherwise leave it.
- [ ] `grep -n "silent no-op\|silently no-ops" docs/security.md` returns empty.

**Per-file scope review.**

### Task 9 — End-to-end verify

- [ ] `go test ./...` — all green.
- [ ] (Optional) Manual smoke: `docker compose up -d`, log in as admin, set access TTL = 10 min in `/admin/settings/tokens`, drive OIDC login, decode access JWT, confirm `exp - iat == 600`.
- [ ] Delete `docs/plans/token-ttl-wiring.md` (this file) in a final commit before opening PR.
- [ ] Open PR. Suggested title: `fix(authserver): wire token TTLs to instance_config`.
- [ ] Suggested commit/PR body:
  ```
  Admin UI at /admin/settings/tokens previously wrote
  access_token_ttl_secs + refresh_token_ttl_secs into instance_config,
  audited the change, and rendered the stored values — but the signing
  path read hardcoded Go constants (oidc.AccessTokenTTL,
  oidc.IDTokenTTL, authserver/token.go:refreshTokenTTL), so edits were
  silent no-ops.

  TokenHandler now reads both TTLs from instance_config at issuance
  time via instanceconfig.Service. Claim builders accept ttl as a
  param. ID token TTL = access TTL. Refresh rotation still preserves
  the original absolute expiry ceiling; refresh TTL config only
  affects new refresh tokens minted from new auth_code exchanges.

  Removes the corresponding "Known limitations" bullet from
  docs/security.md.
  ```

## 7. Testing summary

- **Unit:** `internal/oidc/claims_test.go` — TTL param applied correctly on both builders with distinct values.
- **Integration:** `test/integration/token_ttl_dynamic_test.go` — 3 cases (default / custom / rotation ceiling).
- **Existing:** `test/integration/settings_test.go` write-through tests stay unchanged.

## 8. Out of scope (do NOT add to this PR)

- Separate `id_token_ttl_secs` admin key.
- Caching TTLs in handler struct.
- Backfill pass over existing refresh tokens in Valkey.
- Setup-wizard UI surfaces for TTL (stays under `/admin/settings/tokens`).
- Per-client TTL overrides.

## 9. Migration / rollback

No schema change. `instance_config` rows already exist and are seeded at `internal/database/migrations/000001_baseline.up.sql:127-128`.

Rollback: revert the PR. Constants return. Admin UI once again silently no-ops. No data loss.
