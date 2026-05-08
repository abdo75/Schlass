# Audit Log System — Specification

**Status:** Draft v1
**Owner:** Schlass core
**Last revised:** 2026-04-30
**Visibility:** Internal (gitignored under `/docs/*`)

This document is the source-of-truth spec for the Schlass audit-logging
subsystem. It supersedes every ad-hoc decision made during the Sprint-7 audit
viewer work. Any future audit-related change must trace back to a requirement
ID (`REQ-AUD-NNN`) defined here. The companion implementation plan lives at
`docs/plans/audit-log-system.md` and references these IDs by number.

The spec is deliberately stricter than what we ship today; the gap is what the
plan exists to close.

---

## 1. Scope and goals

The audit log is the legal, security, and operational record of every
sensitive event that occurs inside a Schlass deployment. It is consumed by
three audiences with different needs:

1. **Compliance auditors** (SOC 2 Type II, ISO 27001, GDPR Art 30/32)
   reviewing evidence of control effectiveness over a window.
2. **Incident responders** reconstructing what an actor did, when, and why a
   request succeeded or failed.
3. **Tenant admins** answering "what happened to my account / my user / my
   client" via the in-product viewer.

The system must satisfy all three from a single canonical event store. We do
not maintain divergent logs for "security" vs "ops" vs "UX" — divergence is
how audit trails go missing.

### Deployment model assumed by this spec

Schlass today is **single-tenant per deployment**: one `instance_config` row,
no `tenants` table, one logical customer per running instance. The spec is
written so that introducing multi-tenancy later is a localized change, not a
schema reshape — fields and RLS hooks marked "multi-tenant" are present in
intent but operate as no-ops in single-tenant deployments. Requirements that
apply only when multi-tenancy ships are tagged `(multi-tenant only)`.

### Non-goals

- Application-debug logging (stdout traces, panics, slow-query logs). Those
  belong in the structured app log, not the audit log.
- Metrics, counters, dashboards. Those derive from app logs and Prometheus.
- Long-term raw HTTP access logs. The audit log records semantic events
  ("user logged in"), not transport-level traffic.

---

## 2. Compliance baselines we conform to

The system MUST be designed to produce evidence that satisfies, simultaneously:

- **NIST SP 800-92 rev 1** — log management lifecycle.
- **NIST SP 800-53 AU family**, specifically AU-2 (event selection),
  AU-3 (record content), AU-9 (protection of audit information),
  AU-10 (non-repudiation), AU-12 (audit generation).
- **SOC 2** Trust Services Criteria CC6.1, CC6.6, CC7.2, CC7.3, CC7.4. The
  2026 update tightens evidence expectations around logical-access logging.
- **ISO/IEC 27001:2022** Annex A.8.15 (Logging) and A.8.16 (Monitoring).
- **OWASP Logging Cheat Sheet** and **OWASP ASVS V7** application-layer
  logging requirements.
- **GDPR** Art 30 (records of processing) and Art 32 (security of processing).
  Lawful retention, pseudonymization of subject IDs, justified access.
- **OpenID Shared Signals Framework** + **CAEP 1.0** (final 2025-09-02) for
  outbound event sharing across federations. We design our internal record
  shape so that producing a CAEP-compliant SET is a projection, not a
  rewrite.

---

## 3. Event taxonomy (what we log)

Every audit-relevant operation falls into one of the categories below. The
list is exhaustive for v1; new event types must be added under an existing
category, with a new dotted `event_type` and a row in
`internal/audit/registry.go`.

### REQ-AUD-001 — Authentication

| event_type | Trigger |
|---|---|
| `auth.login.succeeded` | Primary credential accepted. |
| `auth.login.failed` | Primary credential rejected (bad password, unknown user — must not distinguish in actor-visible reason). |
| `auth.mfa.challenged` | MFA challenge issued. |
| `auth.mfa.succeeded` | MFA factor verified. |
| `auth.mfa.failed` | MFA factor rejected. |
| `auth.account.locked` | Lockout threshold tripped. |
| `auth.account.unlocked` | Lockout cleared (timer or admin). |
| `auth.password.changed` | User-initiated password change. |
| `auth.password.reset_requested` | Reset email/code generated. |
| `auth.password.reset_consumed` | Reset token used (success or failure). |
| `auth.stepup.required` | Sensitive op demanded recent-MFA. |
| `auth.stepup.satisfied` | Recent-MFA proven for sensitive op. |
| `auth.risk.flagged` | Risk engine raised the score above threshold (impossible travel, new device, breached-password hit). |

### REQ-AUD-002 — Session lifecycle

`session.created`, `session.refreshed`, `session.revoked`,
`session.idle_timeout`, `session.forced_logout` (admin or system),
`session.concurrent_cap_hit`.

### REQ-AUD-003 — OIDC / OAuth protocol

`oidc.authorize.succeeded`, `oidc.authorize.failed`,
`oidc.token.issued` (one row per `grant_type`),
`oidc.token.refreshed`, `oidc.token.revoked`, `oidc.token.introspected`,
`oidc.consent.granted`, `oidc.consent.revoked`,
`oidc.client_credentials.failed`, `oidc.pkce.failed`,
`oidc.redirect_uri.mismatched`, `oidc.userinfo.served`.

### REQ-AUD-004 — Authorization changes

`authz.role.granted`, `authz.role.revoked`,
`authz.permission.granted`, `authz.permission.revoked`,
`authz.group_membership.added`, `authz.group_membership.removed`,
`authz.policy.changed`.

### REQ-AUD-005 — Administrative actions

User CRUD, client CRUD, signing-key rotate / retire / emergency-retire,
instance-config change, MFA enroll-on-behalf-of, MFA reset, password reset
on behalf of, tenant lifecycle.

### REQ-AUD-006 — Privacy and security operations

`audit.viewed`, `audit.exported`, `audit.retention.changed`,
`audit.purge.executed`, `pii.pseudonymize.rotated`,
`signing_key.accessed` (private-half read by signing path is NOT logged
per-use; key material *export* or *administrative read* IS).

### REQ-AUD-007 — Denials and rate limits

Every endpoint that returns 401 / 403 / 429 on a protected path emits a
denial event. Denials are first-class — they are usually the most useful
record during incident response. `auth.denied`, `authz.denied`,
`ratelimit.tripped`.

### REQ-AUD-008 — Setup and bootstrap

`setup.started`, `setup.completed`, `setup.config.changed`. These are
already logged today; keep them aligned with the same record shape.

---

## 4. Record schema

### REQ-AUD-010 — Required fields on every row

```
event_id           UUIDv7, server-generated, primary key
event_type         dotted, stable, versioned via schema_version
schema_version     int, increment on breaking field changes
event_timestamp    RFC3339Nano UTC; the moment the event occurred
recorded_at        RFC3339Nano UTC; the moment the row was written
                   (event_timestamp != recorded_at; clock skew is real)
outcome            enum { success, failure, denied }
reason_code        stable short string, e.g. "invalid_password",
                   "redirect_uri_mismatch". Free-form prose belongs
                   in metadata.
actor_type         enum { user, service, system, anonymous }
actor_id           HMAC-pseudonymized stable ID (see §6); NULL for system
actor_session_id   when applicable
target_type        enum: user | client | session | signing_key | role |
                   instance | audit_log | mfa_factor | password_reset | …
target_id          HMAC-pseudonymized stable ID; NULL allowed
                   (e.g. "list all users")
tenant_id          (multi-tenant only) mandatory once tenants ship;
                   in single-tenant deployments the column exists and is
                   set to a fixed deployment-wide constant so the schema
                   does not change later
source_service     which Schlass component emitted the event
                   (authserver, users, settings, audit, …)
client_ip_coarse   /24 for v4, /48 for v6; never the full address
                   unless under explicit legal hold
client_ua_family   parsed family + major (e.g. "Firefox/126"), not
                   the raw UA string
client_geo_coarse  country + region; never city or coordinates
request_id         W3C `traceparent` if present, else internal request UUID
correlation_id     groups related events (e.g. authorize → token →
                   userinfo for one user-flow)
metadata           JSONB; non-load-bearing detail. Never authoritative
                   for query.
prev_hash          SHA-256 of the previous row's canonical hash
                   (see §5)
row_hash           SHA-256 of canonical(this row including prev_hash)
```

### REQ-AUD-011 — Forbidden in `metadata`

The following MUST NEVER appear in `metadata`, neither in plaintext nor
encoded: passwords, password hashes, OTP codes, recovery codes, access
tokens, refresh tokens, ID tokens, authorization codes, signing-key
private halves, full email addresses (use pseudonymized actor_id), full
IPs (use `client_ip_coarse`), session cookies. Enforced by a static lint
rule in CI (`tools/audit-lint`) — not by review attention.

### REQ-AUD-012 — Stable serialization

All hashing operates on a canonical JSON encoding (RFC 8785 JCS) of the
row excluding `row_hash` itself. Field ordering, number formatting, and
unicode normalization MUST be deterministic; otherwise re-verification
will produce false tamper alerts on round-trip.

---

## 5. Integrity

### REQ-AUD-020 — Append-only at the storage layer

The `audit_logs` table grants only `INSERT` and `SELECT` to the
application role `schlass_app`. `UPDATE` and `DELETE` are revoked from
`PUBLIC`. This is **already enforced today** in
`000001_baseline.up.sql`. Retention purge runs under a separate role
(`audit_purge`) granted only the targeted `DELETE` privilege, invoked
explicitly by `audit_admin`, and the purge itself emits
`audit.purge.executed`. The pseudonymization sweeper currently uses a
`SECURITY DEFINER` function (`audit_log_pseudonymize_user`) — that
pattern is preserved; functions running with elevated privileges are
the only path that may UPDATE `audit_logs`, and each is auditable on
its own.

### REQ-AUD-021 — Hash chain

Each row carries `prev_hash` (the previous row's `row_hash`) and
`row_hash` (SHA-256 over canonical(row) including `prev_hash`). The
chain is keyed by `(tenant_id, sequence_no)` where `sequence_no` is a
per-tenant monotonically increasing `BIGINT` allocated from a Postgres
sequence. In single-tenant deployments the tenant key is the fixed
deployment-wide constant; the property is the same. Pseudonymized rows
carry a sentinel `row_hash` of `sha256('pseudonymized:' || id::text)`;
the verifier accepts this sentinel without re-deriving from the row
body.

**Concurrency.** Two concurrent inserters cannot be allowed to read the
same chain head and both compute the same `prev_hash`. The emit-helper
takes a transaction-level advisory lock keyed on `tenant_id`
(`pg_advisory_xact_lock(hashtext(tenant_id))`) before reading the
current head and inserting the new row. The lock is held only for the
duration of the audit insert, never the surrounding business
transaction, so contention is bounded by audit-write latency, not by
the caller. A periodic verifier (`audit-verify` job, daily by default)
walks the chain and alerts on the first break. In multi-tenant
deployments the chain is per-tenant to avoid cross-tenant verification
coupling.

### REQ-AUD-022 — Periodic anchoring

Every N events (configurable, default 10 000) or every T minutes
(default 60), the current chain head is anchored to an external,
admin-controlled write-once destination:

- S3 / GCS Object Lock in COMPLIANCE mode, OR
- a transparency-log endpoint we operate, OR
- a customer-supplied immutable log.

Anchoring defeats a privileged DBA. It is OPTIONAL for free-tier
deployments and MANDATORY for any deployment claiming SOC 2 Type II
readiness. Configured per-instance via `audit.anchor.*` keys in
instance_config.

### REQ-AUD-023 — Verification utility

`schlass audit verify --since=…` re-walks the chain and reports the first
inconsistency (broken hash, missing row, gap in `event_id` ordering). It
runs in CI against a synthetic fixture as a smoke test on every release.

---

## 6. PII and privacy

### REQ-AUD-030 — Pseudonymization

`actor_id` and `target_id` for human subjects MUST be HMAC-SHA-256 of the
internal stable ID with a per-deployment pepper (already implemented under
PR #28). The pepper is rotated on demand by the `pii.pseudonymize.rotated`
operation; rotation re-pseudonymizes in-place via the existing sweeper.

### REQ-AUD-031 — Network and device coarsening

IPs are stored at /24 (v4) or /48 (v6). User-agents are parsed to
family + major version. Geo is country + region only. The full forms
are accessible only through a separately gated, audited "legal hold"
path; this path does not exist by default and must be enabled
per-deployment with a signed admin operation.

**Existing data.** Today's `audit_logs.ip_address INET` stores full
IPs. Coarsening applies **forward only**; existing rows are coarsened
in a one-shot backfill migration that drops the host bits in place.
The backfill emits `pii.pseudonymize.rotated` once on completion. We
do not preserve the original IPs in any side-table — preserving them
would defeat the purpose.

### REQ-AUD-032 — Retention buckets

Three buckets, configurable per deployment:

| Bucket | Default retention | Notes |
|---|---|---|
| Security-relevant | 1 year hot, 6 years cold | auth, authz, admin, OIDC, denials |
| Operational | 90 days | session lifecycle, ratelimit, system-emitted |
| Legal hold | indefinite | entered manually, exits manually |

Retention is enforced by `audit_purge`, which itself emits an audit
event. It NEVER deletes rows under legal hold. Default retention values
are baked into instance_config defaults; per-deployment overrides are
themselves audited via `audit.retention.changed`.

Operational rows in mixed-bucket monthly partitions survive until the
partition crosses `security_hot_days`. This is a consequence of sharing
partitions with security-bucket rows; operators who need tighter
operational expiry must configure smaller partition windows, which is
out of scope for v1.

### REQ-AUD-033 — Subject access requests

GDPR Art 15 / Art 17 access and erasure requests against an end-user
subject MUST be served from the audit log. Erasure replaces the
pseudonymized `actor_id` / `target_id` with a tombstone marker; the
event row itself stays, the link to the natural person is severed.
Pseudonymized rows carry `row_hash = sha256('pseudonymized:' ||
id::text)` so the verifier can distinguish sanctioned GDPR mutation
from tampering without re-hashing the mutated row body.

---

## 7. Access controls

### REQ-AUD-040 — Permission separation

Schlass uses **app-level permissions** (e.g. `audit.list`), not
Postgres roles, for end-user authorization. Three distinct
permissions, never collapsed onto the same grant:

- `audit.view` — read the in-product viewer; deployment-scoped (and
  tenant-scoped once multi-tenancy ships).
- `audit.export` — produce a CSV / NDJSON / CAEP-SET export.
- `audit.admin` — change retention, trigger purge, configure
  anchoring, manage audit pepper rotation.

`audit.admin` is NOT implied by the deployment `admin` permission.
Granting any of the three emits `authz.permission.granted`.

These app-level permissions are distinct from the Postgres roles
(`schlass_app`, `audit_purge`) used at the database layer; the two
hierarchies do not map 1:1 and should not be conflated in code or
docs.

### REQ-AUD-041 — Audit-the-auditor

Every read of the audit log emits `audit.viewed` with the query
parameters in `metadata`. Every export emits `audit.exported` with byte
count and row count. The viewer MUST NOT be able to filter out its own
read events from the result set — viewing the viewer is the point.

### REQ-AUD-042 — Step-up for sensitive operations

Export, retention change, purge, and anchoring configuration each
require a recent (≤5 min) MFA reverification. The step-up event itself
(`auth.stepup.satisfied`) is logged.

### REQ-AUD-043 — Tenant isolation (multi-tenant only)

Once multi-tenancy ships, `tenant_id` is enforced at the row level via
PostgreSQL row-level security policies driven by a session GUC
(`SET LOCAL app.tenant_id = …`), not at the application layer.
Application-layer filtering alone has been the source of cross-tenant
leak CVEs in comparable products.

The current `audit_logs` table already has RLS enabled with
`USING (true)` policies, present for forward compatibility. Tightening
the policies is a multi-tenant-only change; until then the policies
remain permissive but the structural hook is in place.

---

## 8. Egress and interoperability

### REQ-AUD-050 — Outbound streaming

The audit log streams to an external SIEM in real time over one of:

- syslog RFC 5424 with structured-data payload, OR
- OpenTelemetry Logs (OTLP/HTTP), OR
- a CAEP-compliant Security Event Token (SET) push for events that have a
  CAEP mapping (session revoke, credential change).

Streaming is at-least-once. Consumers deduplicate by `event_id`. Failure
to stream does NOT block the originating request (see §9).

### REQ-AUD-051 — CAEP projection

The internal record shape is a strict superset of CAEP. A projection
function `internal/audit/caep.go` produces a CAEP SET from any internal
row whose `event_type` has a registered mapping. Adding CAEP support for
a new event type is a one-line registry change, not a schema change.

### REQ-AUD-052 — Export formats

CSV, NDJSON, and CAEP-SET-JSONL. All three exports include a manifest
file with the chain-anchor proof for the exported range, so the recipient
can verify completeness independent of us.

---

## 9. Failure semantics

### REQ-AUD-060 — Critical events fail closed

If the audit write fails for an event in REQ-AUD-001, REQ-AUD-005, or
REQ-AUD-006, the originating operation MUST fail. We do not authenticate,
mutate state, or rotate keys without a durable record. The user-facing
error is generic; the operator-facing error is explicit.

### REQ-AUD-061 — Non-critical events degrade loudly

For session-lifecycle and denial events, primary audit-write failure
does NOT block the request, but it MUST emit an alertable metric
(`audit_write_failures_total{event_type=…}`). Silent loss is a P0
incident.

A DLQ is **not** part of the primary write path — the primary write is
in-transaction with the originating operation (REQ-AUD-062), so a
failed write means the row never existed and there is nothing to
replay. The DLQ exists only on the **outbound streaming path**
(REQ-AUD-050): if the SIEM push fails, the row is durable in
`audit_logs` and is re-pushed by the streamer's retry loop until
acknowledged.

### REQ-AUD-062 — In-transaction emission

All audit rows for an operation MUST be written in the same database
transaction as the operation itself. Out-of-band emission is forbidden;
it has produced "operation succeeded but the event vanished" outcomes
in our prior code, fixed in PR #31. The single-tx invariant is
enforced by passing a `*sql.Tx` into the emit-helper, never a
`*sql.DB`.

---

## 10. UI / viewer contract

### REQ-AUD-070 — Viewer fields are derived, not stored

The in-product viewer renders human-friendly columns (actor name, target
name, event-type label) by joining on the live system at read time, not
by storing display strings on the audit row. The audit row carries IDs
only. This guarantees that renaming a user does not retroactively rewrite
history.

### REQ-AUD-071 — Stable filter contract

The viewer query API accepts: `event_type` (multi), `actor_id`,
`target_id`, `target_type`, `outcome`, time range, free-text reason
search. Every viewer cell that is filterable must be a clickable link
that re-issues the query with the corresponding filter applied. Today's
implementation drifts from this; closing the drift is a plan milestone.

### REQ-AUD-072 — Empty / NULL handling

NULL `target_id` is legitimate (list operations, system-wide events) and
must render distinctly from "I forgot to fill it in". The viewer renders
NULL targets as the resource type alone (e.g. "Audit log") with a
neutral, non-link cell.

---

## 11. Testing requirements

- **Unit:** every event emitter has a test that asserts the exact
  `event_type`, `outcome`, and required-field presence. No event leaves
  CI without a test.
- **Integration:** end-to-end tests assert that user-visible flows
  produce the expected event sequence in the correct order on the
  correct tenant.
- **Chain verification:** a fixture-based test runs the verifier against
  a known-good chain, a known-tampered chain, and a known-truncated
  chain, asserting the verifier correctly classifies each.
- **PII regression:** a static test scans every emit-call site and
  fails CI if it detects any forbidden key being passed into
  `metadata`. The deny-list is exact-name, not substring, to avoid
  false positives on legitimate keys like `reason_code`. Initial
  list: `password`, `password_hash`, `access_token`, `refresh_token`,
  `id_token`, `authorization_code`, `recovery_code`, `otp_code`,
  `recovery_codes`, `private_key`, `email`, `ip`, `ip_address`,
  `cookie`, `session_cookie`. Extensible via
  `tools/audit-lint/denylist.txt`.
- **Performance (measured, M10 Drill 1):** the audit table is on the
  write hot path. Reference measurement on a single shared Postgres
  18 testcontainer with 8 worker goroutines emitting at 200 ev/s for
  30 s sustained: **p50 = 1.21 ms, p95 = 1.77 ms, p99 = 2.11 ms,
  p99.9 = 5.60 ms**, 6 000 / 6 000 rows verified clean post-burst.
  These are end-to-end emit latencies (BEGIN → advisory lock → chain
  read-and-compute → INSERT → COMMIT), so they include the chain
  cost — the spec's pre-chain target was a placeholder. The
  drill is encoded in `test/integration/audit_load_test.go` behind
  the `loadtest` build tag; re-run on representative hardware before
  binding numbers to an SLO. The reproducer is `make audit-load`,
  with `AUDIT_LOAD_RATE` / `AUDIT_LOAD_DURATION` /
  `AUDIT_LOAD_WORKERS` env knobs for variant runs (e.g. the spec's
  full-burst case is `AUDIT_LOAD_DURATION=30m`).

---

## 12. Gap analysis vs current state (2026-04-30)

### 12.1 Column delta

Today's `audit_logs` columns: `id (UUID v4), event_type, actor_id,
actor_email, target_type, target_id, client_id, ip_address (INET),
outcome, metadata, created_at`.

| Today's column | Spec target | Action |
|---|---|---|
| `id UUID v4` | `event_id UUID v7` | rename + change default; v4 IDs in old rows stay valid |
| — | `schema_version INT` | add, default 1 |
| `event_type` | same | freeze taxonomy under §3 |
| — | `recorded_at TIMESTAMPTZ` | add; `created_at` becomes `event_timestamp` semantically |
| `created_at` | `event_timestamp` | rename or alias |
| `outcome IN ('success','failure')` | `IN ('success','failure','denied')` | widen CHECK |
| — | `reason_code TEXT` | add |
| `actor_id` | same, but always pseudonymized | pseudonymize-on-write |
| `actor_email` | drop | `actor_email` violates REQ-AUD-011; remove column, replace lookups via §10 derived rendering |
| — | `actor_type ENUM` | add |
| — | `actor_session_id` | add |
| `target_type / target_id` | same | keep; widen `target_type` enum |
| — | `tenant_id` | add (single-tenant uses fixed constant) |
| — | `source_service TEXT` | add |
| `ip_address INET` | `client_ip_coarse INET` | one-shot backfill drops host bits |
| — | `client_ua_family TEXT` | add |
| — | `client_geo_coarse TEXT` | add |
| `client_id UUID` | move into `target_id` when target is a client; otherwise drop | normalize |
| — | `request_id TEXT`, `correlation_id UUID` | add |
| `metadata JSONB` | same; deny-listed keys | enforce via `tools/audit-lint` |
| — | `sequence_no BIGINT`, `prev_hash BYTEA`, `row_hash BYTEA` | add for hash chain |

### 12.2 Behavioural gaps

| Requirement | Today | Gap |
|---|---|---|
| REQ-AUD-001..008 taxonomy | partial; ad-hoc names | rationalize and freeze |
| REQ-AUD-010 record schema | see §12.1 column delta | add columns, backfill |
| REQ-AUD-011 forbidden fields | no static check | build `tools/audit-lint` |
| REQ-AUD-012 canonical JSON | not used | adopt RFC 8785 JCS for hashing input |
| REQ-AUD-020 append-only DB perms | **already enforced** (`schlass_app` has only INSERT/SELECT, UPDATE/DELETE revoked from PUBLIC) | none; document the existing constraint and add `audit_purge` role |
| REQ-AUD-021 hash chain | not implemented | retrofit with advisory-lock concurrency control |
| REQ-AUD-022 anchoring | not implemented | implement, gate behind `audit.anchor.*` config |
| REQ-AUD-023 verifier | not implemented | add `schlass audit verify` CLI |
| REQ-AUD-030 pseudonymization | done (PR #28); but `actor_email` column still stores plaintext | drop `actor_email`, finish pseudonymizing `actor_id` on write |
| REQ-AUD-031 IP / UA / geo coarsening | full IP stored, UA not parsed, no geo | one-shot backfill + emit-helper enforcement |
| REQ-AUD-032 retention buckets | no purge job, no cold tier | introduce buckets + `audit_purge` |
| REQ-AUD-033 GDPR erasure | partial via `audit_log_pseudonymize_user` | extend to tombstone `target_id`, formalize SAR endpoint |
| REQ-AUD-040 permission split | `audit.list` + admin only | add `audit.export`, `audit.admin` |
| REQ-AUD-041 audit-the-auditor | view/export emit today | enforce viewer cannot filter out its own reads |
| REQ-AUD-042 step-up MFA | not on export | add for export, retention change, purge, anchoring config |
| REQ-AUD-043 tenant RLS | RLS enabled with `USING (true)` | tighten only when multi-tenancy ships |
| REQ-AUD-050 SIEM streaming | none | implement (syslog or OTLP) |
| REQ-AUD-051 CAEP projection | none | implement |
| REQ-AUD-052 export formats | partial | add CAEP-SET-JSONL + manifest with chain proof |
| REQ-AUD-060 fail-closed on critical | inconsistent | audit each emit site |
| REQ-AUD-061 outbound DLQ | n/a (no streaming yet) | bundle with REQ-AUD-050 |
| REQ-AUD-062 in-tx emission | mostly; regression fixed in PR #31 | enforce by helper signature (`*sql.Tx` only) |
| REQ-AUD-070..072 viewer contract | mid-refactor | finish |

The plan at `docs/plans/audit-log-system.md` slices these into ordered
milestones with explicit acceptance criteria mapped to REQ IDs.

---

## 13. Resolved design decisions

The following questions were raised during spec drafting and resolved
on 2026-04-30 before plan work. Recorded here so the rationale travels
with the spec.

### 13.1 Anchoring destination — operator-supplied, three reference templates

Schlass does NOT operate a shared transparency log on behalf of
self-hosted instances. Reasons:

- It would require us to hold publicly-verifiable records on behalf of
  every customer, with the SLA, key custody, abuse handling, and
  takedown policy that implies.
- It would leak the rate and timing of customers' security events to
  us, regressing privacy.

Instead, the implementation ships three reference anchoring backends,
selectable per-deployment via `audit.anchor.backend` in
`instance_config`:

- `s3` — AWS S3 with Object Lock in COMPLIANCE mode.
- `gcs` — GCS bucket with Bucket Lock retention policy.
- `append_only_file` — local filesystem with the host-level append-only
  attribute set (`chattr +a` on Linux ext4/xfs), for air-gapped
  deployments.

Anchoring is OPT-IN at install time and MANDATORY for any deployment
claiming SOC 2 Type II evidence (already stated in REQ-AUD-022).
Deployments that do not need anchoring pay nothing for the feature.

### 13.2 Client IP storage — three modes, /24 default

REQ-AUD-031 mandated `/24` (v4) and `/48` (v6) coarsening. To
accommodate stricter EU member-state DPA interpretations of GDPR
Recital 26 — under which timing-correlated /24 IPs may still be
treated as personal data — the implementation supports three modes
via `audit.client_ip_mode` in `instance_config`:

| Mode | Behaviour |
|---|---|
| `coarse` (default) | /24 v4, /48 v6 as REQ-AUD-031 |
| `country` | only `client_geo_coarse` retained; IP fields discarded at emit time |
| `off` | no IP, no UA, no geo retained |

The default remains `coarse`. Customers in stricter regulatory regimes
flip the mode at install time. The choice is itself an audit event
(`audit.retention.changed` with `metadata.field="client_ip_mode"`).

### 13.3 CAEP — outbound v1, inbound deferred

Outbound CAEP is in scope for v1 (REQ-AUD-051). It is high-leverage:
when Schlass revokes a session or rotates credentials, downstream RPs
that subscribe to our CAEP feed kill the corresponding sessions
immediately, instead of waiting for the next token refresh.

Inbound CAEP (Schlass receiving signals from upstream IdPs and acting
on them) is OUT of scope for v1. Inbound only applies when Schlass is
federated as an RP behind another IdP, which is not the typical
deployment shape — Schlass *is* the IdP. The implementation cost
(delivery semantics, replay protection, signal-to-action policy
engine) is high and unblocks no current customer flow. Revisit when a
federation deployment lands.

### 13.4 Cold-tier storage — Postgres declarative partitioning + Parquet export, no re-import

The `audit_logs` table is converted to a declaratively partitioned
table partitioned by `RANGE (event_timestamp)` with monthly
partitions. Hot partitions live on the primary tablespace. After the
hot retention window (REQ-AUD-032: 1 year by default), the partition
is detached, exported to compressed Parquet on the configured
anchoring backend, and dropped.

There is **no application-level re-import path** from cold storage
back into the hot table. Cold-tier rows are queryable externally
(Athena, DuckDB, `pg_parquet`) but never re-introduced into the live
DB. Round-tripping audit data through application code re-introduces
the tampering vectors that anchoring exists to defeat.

The hash chain spans partition boundaries cleanly: `prev_hash`
references previous-row state by content, not by physical row
location, so detaching a partition does not break the chain for
remaining rows.

Cold-tier anchor rows in `audit_anchors` use `sequence_no = -YYYYMM` as
a sentinel to distinguish them from chain-head anchors. The negative
encoding cannot collide with real `audit_logs.sequence_no` values, which
are always positive.

Operational rows in a monthly partition that also contains security rows
remain hot until the full partition crosses `security_hot_days`.
Operators who need tighter operational expiry must use smaller partition
windows; monthly partitions are the v1 default.
