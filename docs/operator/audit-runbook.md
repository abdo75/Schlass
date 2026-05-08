# Audit log — operator runbook

Operational reference for the Schlass audit-log subsystem (REQ-AUD-* in
`docs/specs/audit-log-system.md`). Each section answers one question an
operator might face during day-to-day ops, an incident, or a compliance
review.

> **Privilege model.** The application connects as `schlass_app` with
> SELECT + INSERT on `audit_logs` only. Two non-app roles exist for
> sanctioned mutations:
>
> - `audit_purge_runner` (LOGIN) — runs `cmd/audit-purge`.
>   DSN: `SCHLASS_PURGE_DATABASE_URL`.
> - `audit_purge` (NOLOGIN) — owner of `audit_purge_expired()`,
>   the SECURITY DEFINER boundary that performs partition-level
>   DETACH/DROP.
>
> The migrations role owns the table and is the only role that can
> issue ad-hoc DDL or write to `audit_logs` outside the
> `audit_log_pseudonymize_user(uuid)` function.

---

## 1. Read the audit log (in-product viewer)

Path: **Admin → Settings → Audit log**, or `/admin/audit` directly.
Permission: `audit.view`.

What works in the viewer:

- Free-text search on `reason_code` (`q=…`).
- Filter chips for `event_type` (multi-select), `actor_id`,
  `target_id`, `target_type`, `outcome`, and a `from`/`to` date range
  picker. Unknown query params are rejected with HTTP 400 — the API
  contract is closed.
- Click any cell rendered as a link to add it as a filter and reset
  the page cursor to 1.
- The right-hand side panel renders the row's full canonical JSON
  plus a `Verify chain to here` button that calls the verifier API
  for the row's sequence range.

Audit-the-auditor (REQ-AUD-041): the viewer query always includes the
caller's own `audit.viewed` events for the queried window — the user
**cannot** filter out their own reads.

## 2. Export evidence

Path: **Admin → Audit log → Export**.
Permission: `audit.export` **+** step-up MFA within last 5 minutes.

Three formats:

| Format | Use case |
|---|---|
| `csv` | spreadsheet diff, ad-hoc spot checks |
| `jsonl` | machine ingest (line-delimited JSON, one event per line) |
| `caep` | regulator / SOC 2 evidence; Security Event Tokens (RFC 8417), CAEP 1.0 schemas, signed JWS |

Every export is a `.tar.gz` bundle. Inside:

- `audit-export.<csv|jsonl|caep>` — the data file.
- `manifest.json` — sequence range, `row_hash_at_start`,
  `row_hash_at_end`, anchor proof (closest anchor with
  `sequence_no >= max_seq` of the export).

To verify a bundle out-of-band:

```bash
go run ./tools/audit-verify-export \
  --bundle /path/to/audit-export.tar.gz \
  --jwks https://auth.example.com/.well-known/jwks.json   # only for caep
```

Exit 0 on a clean bundle; non-zero with a reason on tamper.

## 3. Verify the hash chain

The chain is always-on. An operator triggers a verification when:

- The integrity gauge alerts (`audit.chain.break.detected`).
- A user reports an export that won't validate.
- After a database restore from backup.

```bash
DATABASE_URL='postgres://schlass_app:…@host/schlass' \
  go run ./cmd/audit-verify
```

Useful flags: `--since=2026-04-01T00:00:00Z`, `--tenant=<uuid>`.

Exit codes: `0` clean / `1` mismatch / `2` gap / `3` operational error.

The verifier prints the offending `sequence_no`, expected vs actual
`row_hash`, and the row's `event_id` so you can pinpoint the diverged
record.

### Recover from a tamper alert

1. **Do not restart the app** — primary writes are unaffected; rushing
   loses forensic state.
2. Run `audit-verify` and capture full output to a file. This is your
   first preserved artifact.
3. Run `psql` as the migrations role:
   ```sql
   SELECT id, sequence_no, event_type, actor_id, recorded_at
     FROM audit_logs
    WHERE sequence_no IN (<break_seq> - 1, <break_seq>, <break_seq> + 1);
   ```
4. Identify the changed row by comparing to the most recent CAEP
   export bundle (which carries the pre-tamper `row_hash_at_end`).
5. Open an incident; do **not** delete the diverged row. The chain is
   evidence, not a bug to clean up.
6. Once the incident is closed, the migrations-role owner can issue a
   `DELETE` only on the tampered row (the chain stays consistent
   below it; rows above it are now legacy in verifier terms).

## 4. Anchor the chain to immutable storage

Three backends, configured via instance config:

| Key | Value |
|---|---|
| `audit.anchor.backend` | `none` (default), `appendfile`, `s3`, `gcs` |
| `audit.anchor.bucket` | bucket name (s3/gcs) |
| `audit.anchor.path` | filesystem path (appendfile) or object prefix |
| `audit.anchor.events_per_anchor` | default `10000` |
| `audit.anchor.interval_secs` | default `3600` |

The anchor job runs in-process (started in `cmd/schlass`). It picks
whichever trigger fires first — N events since last anchor, or T
seconds. Failure is logged and **retried on the next tick**; there is
no inner-loop backoff. Sustained failure is visible via the absence
of new rows in `audit_anchors`.

Anchor proofs are stored in the `audit_anchors` table:

```sql
SELECT sequence_no, backend, proof_ref, anchored_at
  FROM audit_anchors
 WHERE tenant_id = '00000000-0000-0000-0000-000000000000'
 ORDER BY sequence_no DESC LIMIT 5;
```

Cloud backends use **WORM retention** (S3 Object Lock COMPLIANCE,
GCS Bucket Lock). The retention period defaults to
`audit.retention.security_hot_days` (365). Operator must enable
versioning + Object Lock on the bucket before pointing the anchor at
it; the app does not configure the bucket.

## 5. Stream events to a SIEM

| Key | Value |
|---|---|
| `audit.stream.backend` | `none`, `syslog`, `otlp` |
| `audit.stream.endpoint` | URL (HTTPS) — syslog over TCP/TLS, OTLP over HTTP |
| `audit.stream.token_ref` | secret reference (header bearer token) |
| `audit.stream.format` | `raw` (default) or `caep` |

Syslog is RFC 5424 over **TCP/TLS only**. UDP is unsupported by
design — UDP fails silently and breaks at-least-once.

Failed pushes write to `audit_stream_dlq`. The retry worker uses
exponential backoff (15 s → 1 m → 10 m → 1 h → 6 h → 24 h). After 24
hours of failure the entry is dropped and `audit.stream.dropped` is
emitted as a critical event — wire this to PagerDuty.

Inspect DLQ size:

```sql
SELECT count(*), min(created_at) AS oldest
  FROM audit_stream_dlq;
```

## 6. Add a new SIEM target

1. Set the three keys above in `instance_config` (UI: Settings →
   Audit log → Streaming, or via the admin API). Step-up MFA gates
   the change.
2. Restart the app — the worker reads config at boot. Live reload is
   not implemented (intentional: streaming reconfig is rare and
   error-prone, restart-on-change forces a fresh DLQ-drain cycle).
3. Tail the DLQ for the first 30 minutes:
   ```sql
   SELECT event_id, attempt_count, last_error, next_retry_at
     FROM audit_stream_dlq
    ORDER BY next_retry_at ASC LIMIT 20;
   ```
4. Confirm the SIEM is receiving by querying the receiver itself.

## 7. Retention + cold-tier promotion

Three retention buckets (REQ-AUD-032), each driven by registry
metadata in `internal/audit/registry.go`:

| Bucket | Hot days | Cold form |
|---|---|---|
| `security` | `audit.retention.security_hot_days` (365) | Parquet, retained `audit.retention.security_cold_years` (6) |
| `operational` | `audit.retention.operational_days` (90) | dropped on partition expiry |

Schlass partitions `audit_logs` monthly on `event_timestamp`. The
purge runner promotes whole partitions older than the security hot
window to cold (Parquet → anchor backend → DETACH PARTITION → DROP).
Operational-only events do not have partition-level isolation; the
system **skips operational expiry inside a hot partition** and emits
`audit.purge.operational_skipped` instead. This is by design — mid-
chain row deletion would break the hash chain. Operational rows are
removed naturally when the partition crosses `security_hot_days`.

Run the purge runner:

```bash
SCHLASS_PURGE_DATABASE_URL='postgres://audit_purge_runner:…@host/schlass' \
  go run ./cmd/audit-purge \
    --output-dir /var/lib/schlass/audit-cold \
    --dry-run        # list actions without exporting or dropping
```

Drop `--dry-run` to execute. Action emits `audit.purge.executed` per
partition handled.

### Query a cold (Parquet) partition

Cold files are valid Parquet. Use DuckDB:

```bash
duckdb -c "SELECT count(*), min(event_timestamp), max(event_timestamp) \
           FROM '/var/lib/schlass/audit-cold/audit_logs_202503.parquet';"
```

Or join across many monthly files:

```bash
duckdb -c "SELECT actor_id, count(*) \
           FROM read_parquet('/var/lib/schlass/audit-cold/audit_logs_*.parquet') \
           WHERE event_type = 'auth.password.changed' \
           GROUP BY 1 ORDER BY 2 DESC LIMIT 20;"
```

Each Parquet file has its SHA-256 stored in `audit_anchors` —
recipient can re-hash and check before trusting the data.

## 8. GDPR Article 17 (right to erasure)

Path: **Admin → Audit log → Erase user**, or
`POST /api/audit/erase {"user_id": "<uuid>"}`.
Permission: `audit.admin` **+** step-up MFA.

The endpoint runs `audit_log_pseudonymize_user(uuid)` which:

- NULLs `actor_id` and `target_id` where they referenced the user.
- Stamps `metadata.pseudonymized_at = now()`.
- Rewrites `row_hash` to `digest('pseudonymized:' || id, 'sha256')`
  — the verifier accepts this sentinel as opaque-but-continuous, so
  the chain still walks across erased rows.

Cold partitions are **not** rewritten by erasure. The current scope
of erasure is the hot partition; cold-tier erasure is a manual
operator task (re-export the partition without the user's rows, swap
the file, update the anchor). Document this on a per-tenant basis
when the data subject's request lands.

> Note: the audit subsystem does **not** use a pseudonymization
> pepper. Erasure is NULL + stamp, not HMAC. Nothing here to rotate.
> The HMAC pepper documented elsewhere (`SCHLASS_PII_PEPPER`) is for
> the password-reset enumeration-safe lookup, not audit logs.

## 9. Restart safety

The chain is durable across crashes — `Chain.Append` runs inside the
caller's transaction with a per-tenant advisory lock that
auto-releases on commit/rollback. No phantom locks survive a
process exit.

After `docker compose down && up` (or any host restart):

1. The app re-attaches to the existing `audit_logs` partitions; no
   migration runs unless code is newer.
2. The streaming worker re-reads `audit_stream_dlq` and resumes the
   backoff curve where it left off.
3. The anchor job picks up on its next interval tick — anchors don't
   need to be in lock-step with restarts.

Verify on restart:

```bash
go run ./cmd/audit-verify          # exit 0 expected
psql -c "SELECT count(*) FROM audit_stream_dlq;"   # should be 0 in steady state
```

## 10. Migration replay

Migrations are reversible (down → up) up to the latest version. The
suite asserts this in `TestMigrationsUpDownUp`. Caveats:

- **000004 (PII closure)** drops `actor_email` and coarsens IPs.
  Down recreates the column **empty**; original emails are unrecoverable.
- **000008 (partitioning)** rebuilds `audit_logs` as a partitioned
  table by recreating it. Down does the reverse. The migration is
  the heaviest in the branch — backup first on a real-shaped
  database before exercising down on production.

Replay flow on a fresh DB:

```bash
DATABASE_URL=… go run ./cmd/migrate -direction=up
DATABASE_URL=… go run ./cmd/migrate -direction=down -steps=1
DATABASE_URL=… go run ./cmd/migrate -direction=up
```

## 11. Step-up MFA for sensitive ops

These endpoints require recent (≤5 min) MFA:

- `POST /api/audit/export` (`audit.export`)
- `PUT  /api/audit/retention` (`audit.admin`)
- `POST /api/audit/purge` (`audit.admin`)
- `PUT  /api/audit/anchor` (`audit.admin`)
- `POST /api/audit/erase` (`audit.admin`)

The frontend wraps each action in `StepUpModal`. On 401 with body
`{"error":"stepup_required"}`, `POST /api/auth/stepup/challenge` with
a TOTP code (or a recovery code via the modal's secondary path), then
retry the original action. `last_mfa_at` is stamped on the Valkey
session.

## 12. Measured performance baseline

Drill 1 (M10) — 200 events/sec sustained, 30 s burst, single shared
Postgres container, 8 worker goroutines:

| Metric | Value |
|---|---|
| Achieved rate | 200.0 ev/s |
| p50 latency | 1.21 ms |
| p95 latency | 1.77 ms |
| p99 latency | 2.11 ms |
| p99.9 latency | 5.60 ms |
| Rows verified | 6000 / 6000 |

Re-run on representative hardware before SLO-binding numbers:

```bash
AUDIT_LOAD_DURATION=30m AUDIT_LOAD_RATE=500 make audit-load
```

Knobs: `AUDIT_LOAD_RATE`, `AUDIT_LOAD_DURATION`, `AUDIT_LOAD_WORKERS`.

## 13. Configuration key summary

| Key | Default | Notes |
|---|---|---|
| `audit.client_ip_mode` | `coarse` | `coarse` (/24, /48) \| `country` \| `off` |
| `audit.anchor.backend` | `none` | `none` \| `appendfile` \| `s3` \| `gcs` |
| `audit.anchor.bucket` | — | bucket name |
| `audit.anchor.path` | — | filesystem path / object prefix |
| `audit.anchor.events_per_anchor` | `10000` | trigger 1 |
| `audit.anchor.interval_secs` | `3600` | trigger 2 |
| `audit.retention.security_hot_days` | `365` | partition promotion threshold |
| `audit.retention.security_cold_years` | `6` | retained in cold tier |
| `audit.retention.operational_days` | `90` | partition-level only |
| `audit.cold_tier.backend` | `same_as_anchor` | or any anchor backend |
| `audit.stream.backend` | `none` | `none` \| `syslog` \| `otlp` |
| `audit.stream.endpoint` | — | URL |
| `audit.stream.token_ref` | — | secret reference |
| `audit.stream.format` | `raw` | `raw` \| `caep` |

Edits to any of these go through `PUT /api/instance-config` with
`audit.admin` + step-up MFA.
