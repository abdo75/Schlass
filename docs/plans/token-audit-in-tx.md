# Plan — `authserver/token.go` audit-in-tx gap

**Branch**: `fix/token-audit-in-tx`
**Base**: `main` (`010df82`)
**Implementer**: Codex
**Reviewer**: Claude

## Problem

`internal/authserver/token.go` `handleAuthorizationCode` calls `codeStore.ConsumeOnce` inside a tx, then at six failure branches commits the tx (destroying the code) without writing an audit row. Forensic gap: a code is burned with no trail. The existing `oidc.code.user_disabled` audit at L210 is the correct pattern; the other six branches do not follow it.

The audit-in-tx rule in `CLAUDE.md` § Audit-in-tx requires every state-changing op to write an `audit_logs` row in the same PG tx as the state change. `ConsumeOnce` is the state change (row mutation marking code consumed), so each commit path must audit.

## Scope

**One file modified**: `internal/authserver/token.go`.
**One test file added**: `test/integration/oidc_token_audit_failures_test.go`.
**No migrations, no API changes, no behavioural change to RP responses.** Only audit rows added.

## Six branches to fix

All live in `handleAuthorizationCode`. Line numbers are approximate against `010df82` and will drift as you edit.

| # | Site | Current behaviour | New audit event |
|---|------|-------------------|-----------------|
| 1 | `row.ClientID != client.ID` (~L184) | `_ = tx.Commit(...)` then `invalid_grant` | `oidc.code.client_mismatch` |
| 2 | `row.RedirectURI != redirectURI` (~L191) | same | `oidc.code.redirect_mismatch` |
| 3 | `!oidc.VerifyPKCE(...)` (~L197) | same | `oidc.code.pkce_mismatch` |
| 4 | `userStore.GetByID` err (~L203) | same | `oidc.code.user_not_found` |
| 5 | `!allowsAuthCode` (~L240) | same | `oidc.code.grant_removed` |
| 6 | `intersectScopesAgainstClient` err (~L246) | same | `oidc.code.scope_removed` |

## Implementation pattern

Match the existing L210 `oidc.code.user_disabled` block exactly. Before the `tx.Commit(...)` call at each site, insert:

```go
if auditErr := h.auditStore.Log(r.Context(), tx, audit.Entry{
    EventType:  "oidc.code.<reason>",
    ActorID:    <see actor rules below>,
    ActorEmail: <see actor rules below>,
    TargetType: "client",
    TargetID:   client.ID.String(),
    ClientID:   &client.ID,
    IPAddress:  extractClientIP(r),
    Outcome:    "failure",
    Metadata:   map[string]any{"family_id": row.FamilyID.String()},
}); auditErr != nil {
    slog.Error("token: <reason> audit", "error", auditErr)
}
if err := tx.Commit(r.Context()); err != nil {
    writeTokenError(w, http.StatusInternalServerError, "server_error", "Could not commit.")
    return
}
writeTokenError(w, http.StatusBadRequest, "<same oauth error as before>", "<same description>")
return
```

Audit log error is swallowed with `slog.Error` (best-effort inside the tx). Do NOT abort the response on audit failure — the code is already burned, response must match the pre-fix shape.

### Actor rules per branch

At branches 1, 2, 3 no user is loaded yet — only the auth-code row. The row carries `UserID`:
- `ActorID: &row.UserID`
- `ActorEmail: ""` (unknown at this point; do not fabricate; columns allow empty string per existing schema)

At branch 4 the `GetByID` lookup failed; only `row.UserID` exists:
- `ActorID: &row.UserID`
- `ActorEmail: ""`
- Metadata includes `"user_id": row.UserID.String()` for forensics.

At branches 5 and 6 the user `u` is loaded and active:
- `ActorID: &u.ID`
- `ActorEmail: u.Email`

Branch 6 metadata should include `"requested_scopes": row.Scopes` and `"allowed_scopes": client.AllowedScopes` so the forensic trail shows the narrowing that produced `invalid_scope`.

### Preserved behaviour

- Same HTTP status codes (`400 invalid_grant` / `400 unauthorized_client` / `400 invalid_scope`) and descriptions.
- Same `tx.Commit` ordering — audit writes into the committed tx, response goes out after commit.
- No changes to the happy path, `handleCodeReplay`, `handleRefreshToken`, or any helper.
- `handleRefreshToken` is intentionally out of scope; it already uses `writeBestEffortAudit` on its failure branches. Do not touch it in this PR.

## Test plan — `test/integration/oidc_token_audit_failures_test.go`

One new file. Use the existing `httptest` env from `oidc_token_auth_code_test.go` (`env := newEnv(t); t.Cleanup(env.close)`). For each branch, build a scenario that forces that specific failure, exchange the code at `/token`, then assert:

1. HTTP response shape unchanged (status + `error` field) — guards against regressions in caller-visible behaviour.
2. Exactly one new `audit_logs` row with `event_type = <expected>` and `outcome = "failure"`.
3. `target_type = "client"`, `target_id = <client uuid>`, `client_id = <client uuid>`, `ip_address` non-empty.
4. `family_id` present in metadata.
5. Actor fields match the rules above (branches 1-4: no email; branches 5-6: actor email matches user).

One sub-test per branch using `t.Run`. Table-driven is fine if helpers stay readable; do not over-abstract.

Reuse `countAuditRows` + the authorize-then-token helpers already in the integration suite. If a helper is missing for a specific branch scenario, add it locally to the new test file — do not modify unrelated test files.

Six sub-tests mapping one-to-one with the table above. Each must fail without the fix applied to `token.go`.

## Non-goals / out of scope

- `handleRefreshToken` audit hardening. Documented exception already; separate PR if ever needed.
- Changing audit row shape or adding new audit columns.
- Touching `handleCodeReplay`. Already writes `oidc.code.replay_detected`.
- Any migration or schema change.
- Any changes to `CLAUDE.md` or `docs/architecture.md`. Claude will update architecture.md on review; do not edit it here.

## Definition of done

- All 20+ existing integration tests still pass (`make test-integration`).
- New test file passes and fails without the fix (spot-check by reverting `token.go` to base).
- `go vet ./...` and `golangci-lint run` clean.
- Commit message: `fix(authserver): audit token-exchange failure branches in-tx`.
- One commit for source + tests. Plan file stays on the branch; Claude deletes it pre-merge.

## Handoff checklist for Codex

- [ ] Pull `fix/token-audit-in-tx` branch.
- [ ] Read this plan end-to-end.
- [ ] Implement the six audit entries per the pattern + actor rules.
- [ ] Write the six sub-tests in the new integration file.
- [ ] Run `make test-unit` + `make test-integration`.
- [ ] Push + open PR titled `fix(authserver): audit token-exchange failure branches in-tx`.
- [ ] PR body links this plan path: `docs/plans/token-audit-in-tx.md`.
