# Audit Log System — Implementation Plan

> **AGENT EXECUTION RULE — NO PRs, ONE BRANCH.** All work lands on the
> long-lived branch `feat/audit-log`. Do **NOT** open pull requests for
> milestones. Do **NOT** merge to `main`. The user reviews and merges
> the entire branch in one squash-merge after the final battle-test
> milestone (M10) passes.
>
> **Commits inside the branch are allowed** — they are the checkpoints
> that let us bisect later. Make one commit per milestone unless a
> milestone is large enough to warrant 2–3 logical commits. Use the
> commit-message stub at the end of each milestone as reference.

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan
> milestone-by-milestone. Steps use checkbox (`- [ ]`) syntax for
> tracking.

**Goal:** Bring Schlass audit logging from the current ad-hoc state to
the full spec at `docs/specs/audit-log-system.md`. Every change traces
to a `REQ-AUD-NNN` requirement defined in the spec. The branch is
green at every milestone (build + lint + unit + integration), so we
can pause, resume, and bisect without leaving the codebase in a
half-state.

**Spec:** `docs/specs/audit-log-system.md` (gitignored — local only).
**Branch:** `feat/audit-log` (long-lived; squash-merged at end).
**Acceptance gate per milestone:** `make test`, `make lint`, `make
build`, plus the milestone-specific acceptance criteria below.

**Tech stack assumptions** (already in repo):
- Go 1.22+, `chi`-style `http.ServeMux` with method routes, `pgx` pool,
  `golang-migrate` migrations under `internal/database/migrations/`.
- React 19 + TypeScript + Tailwind v4, `@tanstack/react-query`,
  `react-i18next`, Vitest + RTL.
- Tests: Go stdlib `testing`, integration suite under
  `test/integration/`. Postgres via Docker Compose.

---

## Milestone map

| # | Milestone | REQ IDs covered | Subagent class |
|---|---|---|---|
| M0 | Branch + commit existing audit-viewer baseline | — | main thread |
| M1 | Schema baseline + emit-helper signature | 010, 062, 008 | main thread |
| M2 | PII closure (drop `actor_email`, IP coarsen, lint) | 011, 030, 031 | leaf (Sonnet) |
| M3 | Hash chain + verifier CLI | 012, 020, 021, 023 | integration (main thread) |
| M4 | Anchoring backends | 022 | leaf (Sonnet) |
| M5 | Retention + cold-tier partitioning | 032, 033 | integration (main thread) |
| M6 | Permission split + step-up MFA | 040, 041, 042 | leaf (Sonnet) |
| M7 | Frontend viewer polish + filter contract | 070, 071, 072 | leaf (Sonnet) |
| M8 | Outbound streaming + DLQ | 050, 060, 061 | integration (main thread) |
| M9 | CAEP projection + export manifest | 051, 052 | leaf (Sonnet) |
| M10 | Battle-test + cutover prep | all | main thread |

### Frontend thread

The user-visible deliverable is the in-product audit-log viewer. UI
work is spread across multiple milestones rather than one
"frontend" block, because each milestone needs the matching backend
landed first. The frontend thread:

- **M0**: existing viewer code (table, filters, side panel, side-panel
  helpers, settings tab) is committed as the branch baseline.
- **M2**: viewer column projection updated to drop the dropped
  `actor_email` column, falls back to the live `users` join.
- **M5**: settings UI gains controls for the three retention buckets
  and the GDPR-erasure entrypoint.
- **M6**: every protected action (export, retention edit, purge,
  anchor config, erase) gates on a step-up MFA modal. This is the
  largest single UI delta after M0.
- **M7**: dedicated milestone — filter contract, clickable cells,
  NULL-target rendering, snapshot coverage. Closes every drift item
  noted in the working memory.
- **M9**: export-format picker (CSV / NDJSON / CAEP-SET) + manifest
  surfaced in the export confirmation dialog.

By M10 the viewer is in its final shape; M10 itself adds no UI.

---

## M0 — Branch + commit existing audit-viewer baseline

**Goal:** Move from the current dirty working tree on `main` to a
clean long-lived branch whose first commit captures the in-progress
viewer work as one cohesive baseline. Later milestones reshape this
baseline; the parts already polished survive untouched.

### Existing dirty state at branch creation

Per `git status` at planning time, the following are uncommitted on
`main` and represent the working in-product audit-log viewer:

- New files under `internal/audit/`: `export.go`, `handler.go`,
  `list_query.go`, `list_select.go`.
- New migration: `internal/database/migrations/000002_audit_log_viewer.{up,down}.sql`.
- New session helpers: `internal/session/context.go`,
  `internal/session/store_test.go`.
- Modified backend: `internal/audit/store.go`,
  `internal/auth/middleware.go`, `internal/server/router.go`,
  `internal/server/setup.go`, `internal/users/permission.go`,
  `internal/users/permission_test.go`, several others touched by
  the viewer's emit-site enrichment.
- Modified integration tests: `test/integration/oidc_*_test.go`,
  `test/integration/setup_test.go`, `test/integration/users_test.go`.
- New integration tests: `test/integration/audit_viewer_test.go`,
  `test/integration/permission_denied_test.go`.
- Frontend: entire `web/src/features/audit/` directory,
  `web/src/features/settings/AuditLogTab.tsx`,
  `web/e2e/audit-viewer.spec.ts`, modifications to `App.tsx`,
  `AdminLayout.tsx`, `index.css`, all three i18n locale files,
  settings page + tests, settings API helper.
- Misc: `.gitignore` updates.

This work is functional (tests + build green per the working memory),
but does not yet meet the spec — it is the starting point M1–M9
transform.

### Tasks

- [ ] **Step 1:** Confirm baseline against `main`. Pull latest main
  (no merge into the dirty tree yet — the dirty tree stays exactly
  as-is).

  ```bash
  git status                       # confirm the dirty state above
  git fetch origin
  git log origin/main..HEAD        # should be empty; dirty work is unstaged
  ```

- [ ] **Step 2:** Create the branch with the dirty tree intact and
  push for visibility.

  ```bash
  git checkout -b feat/audit-log
  git push -u origin feat/audit-log
  ```

- [ ] **Step 3:** Stage everything currently dirty + untracked under
  the audit-log scope. Be explicit — do NOT use `git add -A`. Add by
  path so we don't accidentally pull in unrelated stray files.

  ```bash
  git add internal/audit/export.go \
          internal/audit/handler.go \
          internal/audit/list_query.go \
          internal/audit/list_select.go \
          internal/audit/store.go \
          internal/auth/mfa.go \
          internal/auth/middleware.go \
          internal/authserver/authorize.go \
          internal/authserver/token.go \
          internal/authserver/userinfo.go \
          internal/instanceconfig/service.go \
          internal/server/router.go \
          internal/server/setup.go \
          internal/session/context.go \
          internal/session/store.go \
          internal/session/store_test.go \
          internal/settings/handler.go \
          internal/settings/validate.go \
          internal/settings/validate_test.go \
          internal/users/handler.go \
          internal/users/permission.go \
          internal/users/permission_test.go \
          internal/audit/store.go \
          internal/database/migrations/000002_audit_log_viewer.up.sql \
          internal/database/migrations/000002_audit_log_viewer.down.sql \
          test/integration/audit_viewer_test.go \
          test/integration/permission_denied_test.go \
          test/integration/oidc_authorize_test.go \
          test/integration/oidc_token_audit_failures_test.go \
          test/integration/oidc_token_refresh_test.go \
          test/integration/oidc_userinfo_test.go \
          test/integration/setup_test.go \
          test/integration/users_test.go \
          web/src/App.tsx \
          web/src/components/AdminLayout.tsx \
          web/src/components/__tests__/AdminLayout.test.tsx \
          web/src/features/settings/SettingsPage.tsx \
          web/src/features/settings/__tests__/SettingsPage.test.tsx \
          web/src/features/settings/api.ts \
          web/src/features/settings/AuditLogTab.tsx \
          web/src/features/audit/ \
          web/src/i18n/locales/de.json \
          web/src/i18n/locales/en.json \
          web/src/i18n/locales/fr.json \
          web/src/index.css \
          web/e2e/audit-viewer.spec.ts \
          .gitignore
  ```

  Run `git status` after staging; nothing audit-related should be
  left untracked or unstaged. If anything is, decide explicitly
  whether it joins the commit or stays out.

- [ ] **Step 4:** Capture baseline before committing — test + build
  green, lint clean.

  ```bash
  make test 2>&1 | tee /tmp/audit-baseline-tests.log
  make lint 2>&1 | tee /tmp/audit-baseline-lint.log
  make build 2>&1 | tee /tmp/audit-baseline-build.log
  ```

  Any failure here is a blocker. Fix before committing — we do not
  want a red baseline.

- [ ] **Step 5:** Commit the baseline. The commit message describes
  what is in the commit, not the project history. Use this message:

  ```
  feat(audit): admin audit-log viewer with filters, side panel, and CSV/JSON export

  Adds an admin-gated audit-log viewer at /admin/audit:

  - Backend: four read endpoints under /api/audit/* gated by a new
    audit.list permission; export to CSV and JSON; sentence-style
    rendering of common event types; in-tx audit emission for the
    new audit.viewed and audit.exported events; two configurable
    instance settings (audit_view_logging_enabled,
    audit_export_max_rows).
  - Frontend: /admin/audit page with timeline, filters, calendar
    range picker, row-click side panel with content modules; viewer
    state driven from URL params; reuse of existing admin layout,
    table, and pagination components.
  - Tests: integration coverage for the four endpoints and the
    permission-denial path; frontend snapshot + interaction tests;
    end-to-end Playwright spec.
  ```

- [ ] **Step 6:** Ad-hoc milestone tracker. Create
  `internal/audit/MILESTONE.md` (this path is added to `.gitignore`
  in the same commit so the file stays local to the branch and never
  travels to main on squash-merge). Body is a checklist of M0..M10.
  Subagents read and update it as they complete steps.

  Commit separately:

  ```
  chore(audit): local milestone tracker for branch progress
  ```

**Acceptance gate:**
- Branch `feat/audit-log` exists, pushed.
- One feature commit captures the existing viewer in a clean,
  testable state.
- One chore commit adds the local milestone tracker.
- `make test`, `make lint`, `make build` all green at HEAD.
- Working tree clean.

**Backout:** `git checkout main && git branch -D feat/audit-log &&
git push origin --delete feat/audit-log`. Nothing on main has
changed; the dirty tree returns by checking out the branch again or
by re-applying `git diff main..feat/audit-log~`.

---

## M1 — Schema baseline + emit-helper signature

**Goal:** Reshape `audit_logs` to the spec's column delta and freeze
the emit-helper signature so every later milestone has stable ground.

**REQ IDs:** REQ-AUD-010, REQ-AUD-062, REQ-AUD-008.

**Files:**
- Create: `internal/database/migrations/000003_audit_baseline.up.sql`
- Create: `internal/database/migrations/000003_audit_baseline.down.sql`
- Modify: `internal/audit/store.go` — emit-helper signature
- Modify: every emit-call site under `internal/audit/`,
  `internal/auth/`, `internal/authserver/`, `internal/users/`,
  `internal/settings/`, `internal/instanceconfig/` to use new
  signature
- Create: `internal/audit/registry.go` — frozen taxonomy from spec §3
- Modify: `internal/audit/store_test.go`
- Create: `test/integration/audit_schema_test.go`

### Tasks

- [ ] **Step 1:** Write the up migration. Add columns:
  `schema_version INT NOT NULL DEFAULT 1`,
  `recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()`,
  `event_timestamp TIMESTAMPTZ NOT NULL DEFAULT now()` (back-fill from
  `created_at`),
  `reason_code TEXT`,
  `actor_type TEXT NOT NULL DEFAULT 'user'` with CHECK (`user | service
  | system | anonymous`),
  `actor_session_id UUID`,
  `tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'`
  (single-tenant constant; document in migration comment),
  `source_service TEXT NOT NULL DEFAULT 'unknown'`,
  `client_ua_family TEXT`,
  `client_geo_coarse TEXT`,
  `request_id TEXT`,
  `correlation_id UUID`,
  `sequence_no BIGINT`, `prev_hash BYTEA`, `row_hash BYTEA` (NULLable
  for now — populated in M3).

  Widen outcome CHECK: drop existing CHECK, add
  `CHECK (outcome IN ('success', 'failure', 'denied'))`.

  Backfill `event_timestamp = created_at` and `source_service`
  best-effort from a `CASE` on existing `event_type` prefix.

  **Do NOT drop `actor_email` or coarsen `ip_address` here** — that's
  M2, kept separate so the M2 backfill is auditable on its own.

- [ ] **Step 2:** Down migration mirrors. Drop the added columns,
  re-narrow the outcome CHECK to `success | failure`. Down must be
  reversible after up has run on a fresh DB.

- [ ] **Step 3:** Run + verify both directions.

  ```bash
  make db-up
  go run ./cmd/migrate -direction=up
  go run ./cmd/migrate -direction=down -steps=1
  go run ./cmd/migrate -direction=up
  ```

- [ ] **Step 4:** Freeze taxonomy in `internal/audit/registry.go`.
  One `var EventTypes = map[string]EventTypeSpec{…}` keyed by the
  dotted name from spec §3. `EventTypeSpec` carries:
  `Category` (auth/session/oidc/authz/admin/privacy/denial/setup),
  `RetentionBucket` (security/operational), `IsCritical` (REQ-AUD-060
  trigger), `OutboundCAEP` (CAEP mapping ID or empty).

  Add a `RegisterEvent(eventType, spec)` self-check in `init()` so
  emitting an unregistered event panics in tests.

- [ ] **Step 5:** Refactor the emit helper. New signature:

  ```go
  func (s *Store) Emit(ctx context.Context, tx *sql.Tx, e Event) error
  ```

  Parameters:
  - `tx` is **required**, never `nil`. Pass-through enforces
    REQ-AUD-062 (in-tx invariant) at the type level.
  - `e Event` is the new struct with all REQ-AUD-010 fields. Build
    via `audit.NewEvent(eventType).WithActor(...).WithTarget(...).WithReason(...)`
    builder, so callers can't accidentally omit required fields.

  **Migrate every call site.** Use `gopls` or `grep -rn 'audit\..*Log\|audit\..*Emit'`
  to find them. There are roughly a dozen across `internal/auth`,
  `internal/authserver`, `internal/users`, `internal/settings`,
  `internal/instanceconfig`, `internal/audit`.

- [ ] **Step 6:** Add an integration test
  `test/integration/audit_schema_test.go` that asserts:
  - Every column from REQ-AUD-010 exists with the expected type.
  - The outcome CHECK accepts `denied`.
  - Inserting an unregistered `event_type` from registry panics.
  - The emit helper rejects a `nil` tx at compile time (use a
    type-assertion test if needed).

- [ ] **Step 7:** Run full test suite.

  ```bash
  make test
  ```

**Acceptance gate:**
- `audit_logs` matches REQ-AUD-010 column list (minus M2/M3 columns).
- Emit helper requires `*sql.Tx`; `nil` is uncallable.
- Every existing emit-call site uses new signature.
- Taxonomy registry is single source of truth; unregistered events
  panic in tests.
- Down migration confirmed reversible.

**Backout:** Down migration + `git revert` of the emit-helper
refactor commit. Migration down is the slower step — re-running up
must be idempotent for re-attempt.

**Commit stub:**

```
feat(audit): schema baseline, taxonomy registry, in-tx helper
```

---

## M2 — PII closure

**Goal:** Eliminate plaintext PII from `audit_logs` and add a static
deny-list lint.

**REQ IDs:** REQ-AUD-011, REQ-AUD-030, REQ-AUD-031.

**Files:**
- Create: `internal/database/migrations/000004_audit_pii_closure.up.sql`
- Create: `internal/database/migrations/000004_audit_pii_closure.down.sql`
- Modify: `internal/audit/store.go` — emit-helper IP coarsening
- Modify: `internal/audit/handler.go` — viewer column projection
  (drop `actor_email` from response)
- Create: `tools/audit-lint/main.go` — static analyzer
- Create: `tools/audit-lint/denylist.txt`
- Modify: `Makefile` + CI pipeline — run `audit-lint` in CI
- Modify: `internal/instanceconfig/service.go` — add
  `audit.client_ip_mode` key (`coarse` | `country` | `off`),
  default `coarse`

### Tasks

- [ ] **Step 1:** Migration `000004` — drop `actor_email`, coarsen
  existing `ip_address` rows in place:

  ```sql
  -- IPv4: zero out host bits (set /24)
  UPDATE audit_logs SET ip_address = set_masklen(ip_address, 24)::cidr::inet
   WHERE family(ip_address) = 4;
  -- IPv6: zero out everything below /48
  UPDATE audit_logs SET ip_address = set_masklen(ip_address, 48)::cidr::inet
   WHERE family(ip_address) = 6;

  ALTER TABLE audit_logs RENAME COLUMN ip_address TO client_ip_coarse;
  ALTER TABLE audit_logs DROP COLUMN actor_email;
  ```

  Down migration **cannot** restore the dropped emails or the lost
  host bits — note this clearly in the down file as a SQL comment.
  Down only renames the column back and re-adds the empty
  `actor_email` column.

- [ ] **Step 2:** Update emit-helper. Coarsening happens at emit
  time, NOT at read time. Read `audit.client_ip_mode` once at startup
  (cached in `instance_config` service); the helper applies the right
  transformation. UA parsing via the `mileusna/useragent` Go library
  (already a dep — verify in `go.mod`; if not, add it).

- [ ] **Step 3:** Build `tools/audit-lint`. Implementation:
  - Walk Go AST under `internal/`.
  - Find every call to `audit.Store.Emit` or any function whose name
    matches `Audit*` / `*Audit*`.
  - Inspect the `metadata` field constructor (a `map[string]any` or
    `map[string]string` literal).
  - Fail if any key in the literal matches an exact name in
    `denylist.txt`.

  `denylist.txt`:

  ```
  password
  password_hash
  access_token
  refresh_token
  id_token
  authorization_code
  recovery_code
  recovery_codes
  otp_code
  private_key
  email
  ip
  ip_address
  cookie
  session_cookie
  ```

- [ ] **Step 4:** Wire into CI.

  ```makefile
  .PHONY: audit-lint
  audit-lint:
      go run ./tools/audit-lint ./internal/...
  ```

  Add `audit-lint` to the `lint` target. CI fails on violation.

- [ ] **Step 5:** Add unit tests for `tools/audit-lint`:
  fixture files under `tools/audit-lint/testdata/` with
  intentional violations + clean cases. Asserts exit codes.

- [ ] **Step 6:** Update viewer (`internal/audit/handler.go`,
  `web/src/features/audit/`) — display name comes from a join on
  `users.email` at read time, not from the dropped column. Spec
  REQ-AUD-070 already requires this; M2 finishes the migration.

**Acceptance gate:**
- `actor_email` column gone.
- All existing `audit_logs` rows have coarsened IPs (verify with
  `SELECT count(*) FROM audit_logs WHERE masklen(client_ip_coarse) > 24`).
- `audit-lint` runs in CI and fails on any forbidden key.
- `audit.client_ip_mode` instance-config key works for all three
  modes; integration test for each.

**Backout:** Down migration + revert. Original emails are lost — this
is intentional; the spec mandates it. Document in branch notes that
M2 is a one-way data change.

**Commit stub:**

```
feat(audit): drop actor_email, coarsen IPs, add audit-lint
```

---

## M3 — Hash chain + verifier CLI

**Goal:** Make `audit_logs` tamper-evident.

**REQ IDs:** REQ-AUD-012, REQ-AUD-020 (document existing), REQ-AUD-021,
REQ-AUD-023.

**Files:**
- Create: `internal/database/migrations/000005_audit_hash_chain.up.sql`
- Create: `internal/database/migrations/000005_audit_hash_chain.down.sql`
- Create: `internal/audit/canonical.go` — RFC 8785 JCS encoder for
  Event records
- Create: `internal/audit/chain.go` — sequence/lock/hash logic
- Create: `internal/audit/chain_test.go`
- Modify: `internal/audit/store.go` — emit calls into `chain.go`
  inside the same tx
- Create: `cmd/audit-verify/main.go` — CLI walking the chain
- Create: `test/integration/audit_chain_test.go` — good chain,
  tampered chain, truncated chain fixtures
- Modify: `internal/database/migrations/000001_baseline.up.sql` is
  NOT touched. Sequence is added in `000005`.

### Tasks

- [ ] **Step 1:** Migration `000005`:

  ```sql
  CREATE SEQUENCE audit_logs_seq AS BIGINT MINVALUE 1 NO CYCLE;
  ALTER TABLE audit_logs
    ALTER COLUMN sequence_no SET NOT NULL,
    ALTER COLUMN sequence_no SET DEFAULT nextval('audit_logs_seq'),
    ADD CONSTRAINT audit_logs_seq_unique UNIQUE (tenant_id, sequence_no);
  ```

  Hashes (`prev_hash`, `row_hash`) stay nullable for one final
  backfill step in this migration that walks existing rows in
  insertion order and computes the chain. Document that backfill
  takes O(N) time on existing data.

- [ ] **Step 2:** RFC 8785 canonical JSON in
  `internal/audit/canonical.go`. Use `gibson042/canonicaljson-go` if
  present, else hand-roll a minimal subset (sorted keys,
  no-whitespace, NFC unicode, exact-form numbers). Test against
  the reference vectors from RFC 8785 §3.2.4.

- [ ] **Step 3:** `chain.go` core function:

  ```go
  func (c *Chain) Append(ctx context.Context, tx *sql.Tx, e Event) error {
      // 1. pg_advisory_xact_lock(hashtext(tenant_id))
      // 2. SELECT row_hash FROM audit_logs
      //    WHERE tenant_id = $1
      //    ORDER BY sequence_no DESC LIMIT 1
      // 3. compute row_hash = sha256(jcs(e || prev_hash))
      // 4. INSERT row with sequence_no from sequence
  }
  ```

  Lock is `pg_advisory_xact_lock` so it auto-releases on tx end.
  Locking on `hashtext(tenant_id)` keeps the lock keyspace small.

- [ ] **Step 4:** Concurrency test in `chain_test.go`: spawn N
  goroutines, each opens its own tx and emits an event. After
  joining, verify (a) all N rows present, (b) `sequence_no` is
  contiguous, (c) chain re-walks cleanly with no breaks.

- [ ] **Step 5:** `cmd/audit-verify`:

  ```
  audit-verify --since=<rfc3339> [--tenant=<uuid>]
  ```

  Walks the chain in `sequence_no` order, recomputes each row's
  expected hash, prints the first mismatch as
  `BREAK at sequence_no=N event_id=… expected=… got=…` and exits
  non-zero. Empty result + zero exit means clean.

- [ ] **Step 6:** Integration tests in
  `test/integration/audit_chain_test.go`:
  - **Good fixture:** insert 100 rows, verify clean.
  - **Tampered fixture:** insert 100 rows, manually `UPDATE` one
    row's `metadata` (use a privileged role since `schlass_app`
    can't UPDATE — this is the test scaffolding, not production
    code), assert verifier reports the break at the right
    sequence_no.
  - **Truncated fixture:** insert 100 rows, `DELETE` row 50 via the
    same privileged role, assert verifier detects the gap.

- [ ] **Step 7:** Wire `audit-verify` into CI as a smoke step
  against a freshly-seeded fixture chain.

**Acceptance gate:**
- All new rows carry `prev_hash` + `row_hash` populated.
- Verifier passes on a clean chain, fails with correct row pointer
  on tampered or truncated chain.
- Concurrency test green.
- CI smoke step passes.

**Backout:** Down migration drops the sequence + hash columns.
Unique constraint dropped. Existing rows survive without chain
metadata. Code path can fall back to non-chained emit if a feature
flag is added (do **not** add the flag — keep emit always-chained
post-M3).

**Commit stub:**

```
feat(audit): tamper-evident hash chain, JCS canonicalization, verifier CLI
```

---

## M4 — Anchoring backends

**Goal:** Ship three reference anchoring backends per spec §13.1.

**REQ IDs:** REQ-AUD-022.

**Files:**
- Create: `internal/audit/anchor/` package
  - `anchor.go` — interface
  - `s3.go` — S3 Object Lock backend
  - `gcs.go` — GCS Bucket Lock backend
  - `appendfile.go` — local append-only file backend
- Create: `internal/audit/anchor_job.go` — periodic job
- Modify: `internal/instanceconfig/service.go` — add
  `audit.anchor.backend`, `audit.anchor.bucket`,
  `audit.anchor.path`, `audit.anchor.events_per_anchor`,
  `audit.anchor.interval_secs`
- Create: `test/integration/audit_anchor_test.go`

### Tasks

- [ ] **Step 1:** Define interface:

  ```go
  type Anchor interface {
      Submit(ctx context.Context, head ChainHead) (ProofRef, error)
      Verify(ctx context.Context, head ChainHead, proof ProofRef) error
  }

  type ChainHead struct {
      TenantID    uuid.UUID
      SequenceNo  int64
      RowHash     []byte
      AnchoredAt  time.Time
  }
  ```

- [ ] **Step 2:** Implement `appendfile.go` first (simplest;
  no cloud creds needed for local CI). Each anchor is a JSONL line
  appended to `<path>/anchors-<yyyymm>.jsonl`. The file path is
  expected to be on a filesystem with `chattr +a`; we don't enforce
  it at the Go layer (operator concern, document in `docs/operator/`).

- [ ] **Step 3:** `s3.go` using AWS SDK v2 with Object Lock in
  COMPLIANCE mode. Each anchor is a small JSON object. Bucket-level
  retention is the operator's job (document); we set
  `ObjectLockMode=COMPLIANCE` and `ObjectLockRetainUntilDate` per
  REQ-AUD-032 hot-retention.

- [ ] **Step 4:** `gcs.go` mirrors S3 using Bucket Lock retention.

- [ ] **Step 5:** Periodic job `anchor_job.go`. Triggers on whichever
  comes first: `events_per_anchor` (default 10000) or
  `interval_secs` (default 3600). Reads current chain head per
  tenant, calls `Submit`, stores the `ProofRef` in a new table:

  ```sql
  CREATE TABLE audit_anchors (
    tenant_id    UUID NOT NULL,
    sequence_no  BIGINT NOT NULL,
    row_hash     BYTEA NOT NULL,
    backend      TEXT NOT NULL,
    proof_ref    TEXT NOT NULL,
    anchored_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, sequence_no)
  );
  ```

  Migration `000006_audit_anchors.up.sql` creates the table.

- [ ] **Step 6:** Integration test exercises `appendfile` end-to-end
  in CI. `s3` and `gcs` are exercised by an opt-in test gated on
  env vars (`AUDIT_S3_BUCKET`, `AUDIT_GCS_BUCKET`); CI skips by
  default.

**Acceptance gate:**
- Three backends compile, all interface-satisfying.
- `appendfile` integration green in CI.
- Anchor job runs on schedule when configured; no-op when
  `audit.anchor.backend = none`.
- `audit_anchors` table populated with proof refs.

**Backout:** Drop the anchor job, drop `audit_anchors` table via
`000006` down. Backends compile but stay dormant.

**Commit stub:**

```
feat(audit): anchoring backends (appendfile, s3, gcs) + periodic job
```

---

## M5 — Retention + cold-tier partitioning

**Goal:** Bucketed retention via partitioning + `audit_purge` role +
monthly Parquet export.

**REQ IDs:** REQ-AUD-032, REQ-AUD-033.

**Files:**
- Create: `internal/database/migrations/000008_audit_partitioning.up.sql`
- Create: `internal/database/migrations/000008_audit_partitioning.down.sql`
- Create: `internal/database/migrations/000009_audit_purge_role.up.sql`
- Create: `internal/database/migrations/000010_audit_purge_runner_role.up.sql`
- Create: `cmd/audit-purge/main.go` — purge CLI
- Create: `cmd/audit-export-cold/main.go` — Parquet export CLI
- Modify: `internal/audit/store.go` — `RetentionBucket` lookup at
  emit time → goes into a new column `retention_bucket TEXT`
- Modify: `internal/instanceconfig/service.go` — add
  `audit.retention.security_hot_days` (default 365),
  `audit.retention.security_cold_years` (default 6),
  `audit.retention.operational_days` (default 90),
  `audit.cold_tier.backend` (default `same_as_anchor`)
- Create: `test/integration/audit_retention_test.go`

### Tasks

- [ ] **Step 1:** Convert `audit_logs` to a partitioned table.
  Postgres requires recreating the table for `PARTITION BY RANGE`.
  Strategy:

  ```sql
  ALTER TABLE audit_logs RENAME TO audit_logs_old;
  CREATE TABLE audit_logs (LIKE audit_logs_old INCLUDING ALL)
    PARTITION BY RANGE (event_timestamp);
  -- Recreate sequences, RLS, grants, policies on new parent.
  -- Create initial partitions: current month + 12 prior months.
  INSERT INTO audit_logs SELECT * FROM audit_logs_old;
  DROP TABLE audit_logs_old;
  ```

  This is the riskiest migration in the plan. **Test the up + down
  on a copy of a real-shaped fixture before merging M5 into the
  branch.** Down recreates the non-partitioned form.

- [ ] **Step 2:** Add `retention_bucket TEXT` column populated from
  `registry.go` at emit time. Backfill existing rows by mapping
  `event_type` prefix → bucket.

- [ ] **Step 3:** `audit_purge` Postgres role + GRANT DELETE only on
  partition tables (not the parent), only inside a `SECURITY
  DEFINER` function `audit_purge_expired()`. The function:
  - Iterates partitions older than `security_hot_days` (cold-tier
    promotion) or older than `operational_days` for operational
    bucket.
  - For cold-tier: `pg_dump` the partition → run
    `cmd/audit-export-cold` to produce Parquet → `chattr +a` the
    Parquet file (or upload to anchor backend) → `DETACH PARTITION`
    → `DROP TABLE`.
  - For operational expiry: just drop the partition, no export.
  - Emits `audit.purge.executed` for each partition processed.

- [ ] **Step 4:** `cmd/audit-export-cold` writes Parquet via
  `apache/arrow` Go bindings or `xitongsys/parquet-go`. One file per
  partition, schema mirrors `audit_logs` columns. SHA-256 of the
  Parquet file is recorded in `audit_anchors` so the cold export is
  itself anchored.

- [ ] **Step 5:** GDPR erasure (REQ-AUD-033): extend
  `audit_log_pseudonymize_user(p_user_id UUID)` to also tombstone
  `target_id` where it points at the user. Add HTTP endpoint
  `POST /api/audit/erase` gated behind `audit.admin` permission +
  step-up MFA (M6 dependency — function ships in M5, endpoint in
  M6).

- [ ] **Step 6:** Integration test: insert events spanning a synthetic
  18-month timeline, run `audit-purge`, assert that operational
  events older than 90 days are gone, security events older than 1
  year are exported as Parquet + dropped from hot, and the chain
  still verifies cleanly across the partition boundary.

**Acceptance gate:**
- `audit_logs` is a partitioned table with monthly partitions.
- Purge job correctly classifies and acts on each bucket.
- Cold-tier Parquet files exist and are referenced from
  `audit_anchors`.
- GDPR erasure tombstones both `actor_id` and `target_id` cleanly.
- Chain verification spans partitions.

**Backout:** Down migration is heavy. Document that M5 is the
hardest checkpoint to revert. Pre-M5 snapshot of the database is
kept as `audit_logs_pre_m5.sql.gz` for the duration of the branch.

**Commit stub:**

```
feat(audit): partitioned retention, audit_purge role, Parquet cold-tier
```

---

## M6 — Permission split + step-up MFA

**Goal:** Replace single `audit.list` permission with `audit.view` /
`audit.export` / `audit.admin`, gate sensitive ops on recent MFA.

**REQ IDs:** REQ-AUD-040, REQ-AUD-041, REQ-AUD-042.

**Files:**
- Modify: `internal/users/permission.go` — add the three permissions
- Modify: `internal/users/permission_test.go`
- Modify: `internal/audit/handler.go` — split route guards
- Create: `internal/auth/stepup.go` — recent-MFA verification helper
- Modify: `internal/audit/handler.go` — wrap `Export`,
  retention-change, purge-trigger, anchor-config endpoints with
  `RequireRecentMFA(5*time.Minute)`
- Modify: `web/src/features/audit/` — split UI surfaces, prompt for
  MFA on protected actions
- Modify: `internal/audit/list_query.go` — viewer cannot filter out
  its own `audit.viewed` reads (REQ-AUD-041)

### Tasks

- [ ] **Step 1:** Add the three permissions to `rolePermissions`.
  Compatibility shim: keep `audit.list` as an alias for `audit.view`
  for one release; remove in M10.

- [ ] **Step 2:** `internal/auth/stepup.go`:

  ```go
  func RequireRecentMFA(d time.Duration) func(http.Handler) http.Handler
  ```

  Reads `last_mfa_at` from the Valkey session; rejects with 401 +
  body `{"error":"stepup_required"}` if older than `d`. Emits
  `auth.stepup.required` on rejection and `auth.stepup.satisfied`
  on success.

- [ ] **Step 3:** Wrap protected endpoints in `audit/handler.go`:
  - `POST /api/audit/export` — `audit.export` + step-up
  - `PUT /api/audit/retention` — `audit.admin` + step-up
  - `POST /api/audit/purge` — `audit.admin` + step-up
  - `PUT /api/audit/anchor` — `audit.admin` + step-up
  - `POST /api/audit/erase` — `audit.admin` + step-up

- [ ] **Step 4:** Audit-the-auditor enforcement: in
  `list_query.go`, the WHERE clause **always** includes the
  caller's own `audit.viewed` events for the queried window, even
  if the caller's filter would exclude them. Implementation: split
  the user's WHERE into a CTE; UNION with a mandatory branch
  selecting `event_type = 'audit.viewed' AND actor_id = caller_id`.

- [ ] **Step 5:** UI: Settings → Audit Log tab gets per-action MFA
  prompts. Reuse the existing step-up modal from password-reset
  flow (PR #28). Translation strings for `en/de/fr`.

- [ ] **Step 6:** Tests — unit on permission map, integration on
  each protected endpoint hitting it without recent MFA (rejected),
  with recent MFA (accepted).

**Acceptance gate:**
- Three permissions present, granted explicitly to roles.
- Each protected endpoint demands recent MFA.
- Audit-the-auditor self-reads cannot be filtered out.
- UI gates each protected action with the step-up modal.

**Backout:** Revert; permission map and route wrapping are local
changes.

**Commit stub:**

```
feat(audit): permission split + step-up MFA on sensitive ops
```

---

## M7 — Frontend viewer polish + filter contract

**Goal:** Close the open drift in the in-product viewer.

**REQ IDs:** REQ-AUD-070, REQ-AUD-071, REQ-AUD-072.

**Files:**
- Modify: `internal/audit/handler.go` — derive display strings at
  read time, never persist them
- Modify: `internal/audit/list_query.go` — stable filter contract
- Modify: `web/src/features/audit/AuditPanel*.tsx`,
  `AuditPage.tsx` — every filterable cell is a clickable link
- Modify: `web/src/features/audit/AuditPanelHelpers.tsx` — NULL
  target_id renders as resource type (neutral, non-link)

### Tasks

- [ ] **Step 1:** Audit every column the viewer renders. For each,
  confirm the value comes from a live join, not a persisted display
  string. Memory notes existing drift in `target_display` — that
  CASE should derive from `target_type` + `target_id` at query time
  only.

- [ ] **Step 2:** Filter contract: viewer query API supports exactly
  `event_type` (multi), `actor_id`, `target_id`, `target_type`,
  `outcome`, `from`, `to`, `q` (free-text reason search). Reject
  unknown query params with 400 (today they may silently no-op).

- [ ] **Step 3:** Every filterable cell in the React panel emits a
  click handler that calls `onFilterChange({…, page: 1})`. Cells
  with no filterable target (e.g. NULL target on a system event)
  render the resource type as plain text, no underline, no
  pointer cursor.

- [ ] **Step 4:** Add Vitest snapshot tests for each cell variant
  (actor link, target link, NULL target, event_type link, outcome
  badge).

**Acceptance gate:**
- All filterable cells are links and filter correctly.
- NULL targets render distinctly from "missing data".
- No persisted display strings remain in `audit_logs`.
- Snapshot tests cover every cell variant.

**Backout:** Pure UI + read-path change; revert is clean.

**Commit stub:**

```
feat(audit): finish viewer filter contract + NULL handling
```

---

## M8 — Outbound streaming + DLQ

**Goal:** Stream audit events to a SIEM with at-least-once
guarantees.

**REQ IDs:** REQ-AUD-050, REQ-AUD-060, REQ-AUD-061.

**Files:**
- Create: `internal/audit/stream/` package
  - `stream.go` — interface
  - `syslog.go` — RFC 5424 backend
  - `otlp.go` — OpenTelemetry Logs HTTP backend
- Create: `internal/audit/dlq.go` — DLQ table writes + retry loop
- Create: `internal/database/migrations/000009_audit_dlq.up.sql`
  (creates `audit_stream_dlq` table)
- Modify: `internal/audit/store.go` — post-tx hook fans out to
  streamer; failure → DLQ
- Modify: `internal/instanceconfig/service.go` — add
  `audit.stream.backend`, `audit.stream.endpoint`,
  `audit.stream.token_ref`

### Tasks

- [ ] **Step 1:** Streaming interface:

  ```go
  type Streamer interface {
      Push(ctx context.Context, batch []Event) error
  }
  ```

  Implementations are HTTP-only (no syslog UDP — UDP is unreliable
  and fails silently). RFC 5424 over TCP/TLS.

- [ ] **Step 2:** DLQ table + retry. Failed pushes write to
  `audit_stream_dlq (event_id, attempt_count, last_error,
  next_retry_at)`. A background worker picks them up with
  exponential backoff. After 24h of failures, emit
  `audit.stream.dropped` and alert.

- [ ] **Step 3:** Fail-closed enforcement on critical events
  (REQ-AUD-060). If the **primary** in-tx write fails for an event
  whose `IsCritical=true` in `registry.go`, the originating
  operation MUST return 500 to the user. The streaming push is
  separate — its failure goes to the DLQ, the originating op
  succeeds. (Spec §9 already says this; this is the implementation
  step.)

- [ ] **Step 4:** Metrics: `audit_write_failures_total{event_type}`,
  `audit_stream_failures_total{backend}`,
  `audit_stream_dlq_size`. Wired into the existing Prometheus
  endpoint (assumed; verify in `internal/server/setup.go`).

- [ ] **Step 5:** Integration test runs both streamers against a
  fake HTTP receiver; asserts at-least-once delivery and DLQ retry
  on injected failures.

**Acceptance gate:**
- Both streamer backends compile and stream end-to-end against a
  fake receiver in CI.
- DLQ retries with backoff; expired entries alert.
- Critical-event in-tx write failure returns 500; non-critical
  degrades + metric increments.

**Backout:** Stop the streamer worker, drop `audit_stream_dlq`
table. Primary write path is unaffected.

**Commit stub:**

```
feat(audit): syslog + OTLP streaming with DLQ retry
```

---

## M9 — CAEP projection + export manifest

**Goal:** Project internal events to CAEP SET format; export bundles
ship with chain-anchor proof.

**REQ IDs:** REQ-AUD-051, REQ-AUD-052.

**Files:**
- Create: `internal/audit/caep.go` — projection function
- Create: `internal/audit/caep_test.go` — tested against CAEP 1.0
  reference vectors from spec §2
- Modify: `internal/audit/registry.go` — populate `OutboundCAEP`
  field for mapped event types
- Modify: `internal/audit/export.go` — add NDJSON + CAEP-SET-JSONL
  formats; emit `manifest.json` with chain-head + anchor proof
- Modify: `internal/audit/stream/` — CAEP push variant for SET
- Modify: `web/src/features/audit/` — export format picker

### Tasks

- [ ] **Step 1:** Map at minimum these event types to CAEP:
  - `session.revoked` → `https://schemas.openid.net/secevent/caep/event-type/session-revoked`
  - `auth.password.changed` → `…/credential-change`
  - `auth.account.locked` → `…/account-disabled`
  - `auth.risk.flagged` → `…/risk-level-change`

  Add the mapping in `registry.go`. Other event types stay
  CAEP-less (`OutboundCAEP=""`) and are simply not pushed.

- [ ] **Step 2:** `caep.go` produces a SET (RFC 8417) signed by the
  same signing key the IdP uses for OIDC. Reuse
  `internal/authserver/signing` package.

- [ ] **Step 3:** Export manifest: every CSV/NDJSON/CAEP-SET export
  bundle is a tarball containing the data file plus
  `manifest.json`:

  ```json
  {
    "exported_at": "2026-04-30T…",
    "tenant_id": "…",
    "sequence_range": [1234, 5678],
    "row_hash_at_start": "…",
    "row_hash_at_end": "…",
    "anchor_proof": { "backend": "s3", "ref": "s3://…/anchor-…" }
  }
  ```

  Recipient can re-walk the chain over the data file and verify it
  matches the manifest, independent of us.

- [ ] **Step 4:** Tests — golden-file tests for each CAEP mapping,
  manifest validation in integration test.

**Acceptance gate:**
- CAEP SET emission matches reference vectors.
- Export bundle ships manifest with anchor proof.
- Recipient verifier (script under `tools/audit-verify-export/`)
  validates a bundle end-to-end.

**Backout:** CAEP is additive; revert leaves the rest in place.
Export reverts to plain CSV/NDJSON without manifest.

**Commit stub:**

```
feat(audit): CAEP SET projection + export manifest with chain proof
```

---

## M10 — Battle-test + cutover prep

**Goal:** Prove the system holds before merging to `main`. No new
features; all stress / drill / burndown.

**REQ IDs:** all (validation, not implementation).

**Files:**
- Create: `test/load/audit_load_test.go` — k6 / vegeta-style load test
- Create: `docs/operator/audit-runbook.md` — operator-facing runbook
  (this one is **NOT** gitignored — `docs/operator/**` is allowed)
- Modify: `MILESTONE.md` — fill in measured numbers

### Tasks

- [ ] **Drill 1 — Load.** 200 events/sec sustained for 30 min on
  the reference Compose stack. Capture p50/p95/p99 added latency.
  Spec target is ≤5 ms p99 (placeholder). Update spec with the
  measured number.

- [ ] **Drill 2 — Chain tamper.** Stop the app, tamper a row via
  `psql` as superuser, restart, run `audit-verify`, assert it
  flags the right row.

- [ ] **Drill 3 — Anchor failure.** Misconfigure S3 creds, observe
  that the anchor job retries with backoff and alerts on sustained
  failure. Audit emit path is unaffected.

- [ ] **Drill 4 — SIEM failure.** Block the SIEM endpoint, observe
  DLQ growth, restore endpoint, observe drain.

- [ ] **Drill 5 — Restart.** `docker compose down && up`. Chain
  resumes cleanly. No events lost. No phantom advisory locks held.

- [ ] **Drill 6 — GDPR erasure.** Erase a user, confirm `actor_id`
  + `target_id` tombstoned across hot + cold tiers, chain still
  verifies, viewer renders erased rows with a tombstone marker.

- [ ] **Drill 7 — Migration replay.** On a fresh DB, run M0→M9
  migrations in order, then in reverse. Confirm down works at
  each step.

- [ ] **Drill 8 — Cold-tier query.** Export a cold partition,
  query it externally with DuckDB, confirm rows match what the hot
  table held before purge.

- [ ] **Operator runbook:** Write `docs/operator/audit-runbook.md`
  covering: how to read the viewer, how to export, how to verify
  the chain, how to recover from a tamper alert, how to rotate the
  pseudonymization pepper, how to add a new SIEM target, how to
  promote cold partitions to long-term storage.

- [ ] **Final sign-off:** All ten milestones green. Branch ready
  for squash-merge to `main`.

**Acceptance gate:**
- All eight drills pass with documented results.
- Operator runbook published under `docs/operator/`.
- Spec performance target updated with measured numbers.

**Backout:** N/A — M10 is verification, not change.

**Commit stub:**

```
chore(audit): battle-test results, operator runbook, cutover prep
```

---

## After M10 — merge to main

User performs the squash-merge. Plan author does NOT.

```bash
git checkout main && git pull --ff-only
git merge --squash feat/audit-log
# review the staged diff one last time
git commit  # message follows the spec section IDs
git push origin main
git push origin --delete feat/audit-log
git branch -D feat/audit-log
```

Squash-merge collapses the milestone commits into one main-history
commit. The per-milestone history stays in the local branch reflog
for ~90 days if a bisect is ever needed retroactively.

---

## Notes for subagent dispatchers

- **Leaf milestones** (M2, M4, M6, M7, M9) are good candidates for
  Sonnet subagents with the milestone section copied verbatim as
  the prompt and the REQ IDs as the acceptance gate.
- **Integration milestones** (M1, M3, M5, M8) stay on the main
  thread because they touch many call sites or do schema reshapes
  that benefit from the broader conversation context.
- M10 is main-thread only; every drill needs human-eyes
  interpretation.
- Per-file scope review (memory: `feedback_per_file_scope_review`)
  applies to every implementation step. Subagents must report
  sufficient/too-much/too-little after each file edit.
