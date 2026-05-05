// Watermark-poll streaming worker. Reads audit_logs rows ahead of the
// per-tenant audit_stream_state.last_seq watermark, pushes each batch
// through the configured Streamer (syslog/otlp), and routes failures to
// audit_stream_dlq. Mirrors the boot pattern used by anchor_job.go.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/audit/stream"
	"github.com/abdo75/Schlass/internal/instanceconfig"
)

// StreamWorker holds boot-time configuration. Constructed at boot and
// owned by the goroutine returned from StartStreamWorker.
type StreamWorker struct {
	pool       *pgxpool.Pool
	cfg        *instanceconfig.Service
	auditStore Logger
	streamer   stream.Streamer
	backend    string
	dlq        *stream.DLQ
}

// NewStreamWorker constructs the worker with the given streamer + label.
// Boot-time wiring uses StartStreamWorker (which calls this internally);
// integration tests use it directly so they can call RunOnce against a
// fake streamer without standing up a ticker goroutine.
//
// DLQ-size gauge registration is intentionally NOT done here — the
// Prometheus default registry is process-global and the gauge closure
// captures whatever pool is passed first. In tests each NewTestEnv
// rebuilds the pool, so a test-side registration would leave the gauge
// querying a closed pool. StartStreamWorker (production boot) owns the
// registration; tests don't need the gauge.
func NewStreamWorker(pool *pgxpool.Pool, cfg *instanceconfig.Service, auditStore Logger, streamer stream.Streamer, backend string) *StreamWorker {
	return &StreamWorker{
		pool:       pool,
		cfg:        cfg,
		auditStore: auditStore,
		streamer:   streamer,
		backend:    backend,
		dlq:        stream.NewDLQ(pool),
	}
}

// StartStreamWorker reads instance_config, builds the configured
// streamer, and runs the watermark loop until ctx is cancelled. When
// audit.stream.backend is "none" (the default) the goroutine returns
// immediately so deployments without SIEM integration pay no cost.
func StartStreamWorker(ctx context.Context, pool *pgxpool.Pool, cfg *instanceconfig.Service, auditStore Logger) {
	backend, err := cfg.AuditStreamBackend(ctx, pool)
	if err != nil {
		slog.Warn("audit stream: read backend, defaulting to none", "error", err)
		backend = "none"
	}
	if backend == "none" {
		slog.Debug("audit stream: backend none, worker exiting")
		return
	}
	streamer, err := buildStreamer(ctx, cfg, pool, backend)
	if err != nil {
		slog.Error("audit stream: build streamer failed", "backend", backend, "error", err)
		return
	}
	defer func() {
		if err := streamer.Close(); err != nil {
			slog.Warn("audit stream: streamer close", "error", err)
		}
	}()
	pollSecs, err := cfg.AuditStreamPollSecs(ctx, pool)
	if err != nil || pollSecs <= 0 {
		pollSecs = 5
	}
	w := NewStreamWorker(pool, cfg, auditStore, streamer, backend)
	// Production boot owns the gauge registration — see NewStreamWorker doc.
	RegisterDLQGauge(pool)

	ticker := time.NewTicker(time.Duration(pollSecs) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.RunOnce(ctx); err != nil {
				slog.Error("audit stream: cycle failed", "backend", backend, "error", err)
			}
		}
	}
}

// RunOnce iterates every tenant once. Per-tenant errors are logged but
// don't abort the cycle (a single tenant's misbehaviour can't gag the
// rest of the deployment).
func (w *StreamWorker) RunOnce(ctx context.Context) error {
	batchSize, err := w.cfg.AuditStreamBatchSize(ctx, w.pool)
	if err != nil || batchSize <= 0 {
		batchSize = 100
	}
	hotDays := w.hotRetentionDays(ctx)
	tenants, err := w.tenants(ctx)
	if err != nil {
		return err
	}
	for _, tenantID := range tenants {
		if err := w.runTenant(ctx, tenantID, batchSize, hotDays); err != nil {
			slog.Error("audit stream: tenant cycle", "tenant_id", tenantID, "error", err)
		}
	}
	return nil
}

func (w *StreamWorker) runTenant(ctx context.Context, tenantID uuid.UUID, batchSize, hotDays int) error {
	if err := w.drainDLQ(ctx, tenantID, batchSize); err != nil {
		// Continue to forward stream — a transient DLQ failure must not
		// block fresh events.
		slog.Warn("audit stream: dlq drain", "tenant_id", tenantID, "error", err)
	}
	return w.forwardStream(ctx, tenantID, batchSize, hotDays)
}

// hotRetentionDays reads audit.retention.security_hot_days for partition
// pruning of the forward-stream query. M5 partitioned audit_logs by
// event_timestamp, so any predicate that does not reference
// event_timestamp scans every partition. Falls back to 365 (the
// migration default) on read error so a transient instance_config
// glitch never silently disables pruning.
func (w *StreamWorker) hotRetentionDays(ctx context.Context) int {
	d, err := w.cfg.AuditRetentionSecurityHotDays(ctx, w.pool)
	if err != nil || d <= 0 {
		return 365
	}
	return d
}

// drainDLQ retries every due DLQ row for a tenant, bumping or dropping
// each based on outcome and age. Each row is pushed individually
// (single-event "batch") because each retry has an independent next
// retry schedule.
func (w *StreamWorker) drainDLQ(ctx context.Context, tenantID uuid.UUID, limit int) error {
	rows, err := w.dlq.ListDue(ctx, tenantID, limit)
	if err != nil {
		return err
	}
	for _, r := range rows {
		// Drop rows older than MaxRetainAge before another push attempt
		// so we don't burn throughput on doomed deliveries.
		if time.Since(r.CreatedAt) > stream.MaxRetainAge {
			if err := w.markDroppedAndAudit(ctx, r); err != nil {
				slog.Error("audit stream: mark dropped", "tenant_id", tenantID, "seq", r.SequenceNo, "error", err)
			}
			continue
		}
		evt, err := w.fetchEvent(ctx, tenantID, r.SequenceNo)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				// Source row is gone (cold-tier purge etc). Drop the
				// DLQ entry — there's nothing to retry.
				if delErr := w.dlq.Delete(ctx, tenantID, r.SequenceNo); delErr != nil {
					slog.Warn("audit stream: delete orphan dlq", "tenant_id", tenantID, "seq", r.SequenceNo, "error", delErr)
				}
				continue
			}
			slog.Warn("audit stream: fetch retry source", "tenant_id", tenantID, "seq", r.SequenceNo, "error", err)
			continue
		}
		pushCtx, cancel := context.WithTimeout(ctx, stream.PushTimeout)
		err = w.streamer.Push(pushCtx, []stream.Event{evt})
		cancel()
		if err != nil {
			IncStreamFailure(w.backend)
			if bumpErr := w.dlq.BumpFailure(ctx, tenantID, r.SequenceNo, err.Error()); bumpErr != nil {
				slog.Warn("audit stream: bump failure", "tenant_id", tenantID, "seq", r.SequenceNo, "error", bumpErr)
			}
			continue
		}
		if delErr := w.dlq.Delete(ctx, tenantID, r.SequenceNo); delErr != nil {
			slog.Warn("audit stream: delete after retry", "tenant_id", tenantID, "seq", r.SequenceNo, "error", delErr)
		}
	}
	return nil
}

// forwardStream reads new audit_logs rows ahead of the watermark and
// pushes them. Outcomes:
//   - Push success → watermark advances to max(seq) in the batch.
//   - Push failure + DLQ enqueue success → watermark advances past the
//     failed batch so retries are exclusively driven by the DLQ.
//   - Push failure + DLQ enqueue failure → watermark stays put, return
//     error; the next cycle re-reads the same rows.
//
// The query is bounded by `event_timestamp >= now() - <hot_days> days`
// so the planner can prune cold partitions (M5 partitioned audit_logs
// by event_timestamp). Without this bound, every poll scans the full
// table including years of cold security data.
func (w *StreamWorker) forwardStream(ctx context.Context, tenantID uuid.UUID, batchSize, hotDays int) error {
	lastSeq, err := w.readWatermark(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("audit stream: read watermark: %w", err)
	}
	rows, err := w.pool.Query(ctx,
		`SELECT id, tenant_id, sequence_no, event_type, event_timestamp, outcome, reason_code,
		        actor_type, actor_id, actor_session_id, target_type, target_id,
		        source_service, client_ip_coarse, client_geo_coarse, client_ua_family,
		        request_id, correlation_id, retention_bucket, metadata
		   FROM audit_logs
		  WHERE tenant_id = $1
		    AND sequence_no > $2
		    AND event_timestamp >= now() - ($4 * INTERVAL '1 day')
		    AND NOT EXISTS (
		      SELECT 1 FROM audit_stream_dlq d
		       WHERE d.tenant_id = audit_logs.tenant_id
		         AND d.sequence_no = audit_logs.sequence_no
		    )
		  ORDER BY sequence_no
		  LIMIT $3`,
		tenantID, lastSeq, batchSize, hotDays,
	)
	if err != nil {
		return fmt.Errorf("audit stream: query forward: %w", err)
	}
	defer rows.Close()
	var batch []stream.Event
	for rows.Next() {
		evt, err := scanEvent(rows)
		if err != nil {
			return fmt.Errorf("audit stream: scan: %w", err)
		}
		batch = append(batch, evt)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("audit stream: rows: %w", err)
	}
	if len(batch) == 0 {
		return nil
	}
	pushCtx, cancel := context.WithTimeout(ctx, stream.PushTimeout)
	pushErr := w.streamer.Push(pushCtx, batch)
	cancel()
	maxSeq := batch[len(batch)-1].SequenceNo
	if pushErr != nil {
		IncStreamFailure(w.backend)
		entries := make([]stream.PendingEntry, 0, len(batch))
		for _, e := range batch {
			entries = append(entries, stream.PendingEntry{
				AuditID: e.ID, TenantID: e.TenantID, SequenceNo: e.SequenceNo,
			})
		}
		if dlqErr := w.dlq.Enqueue(ctx, entries, pushErr.Error()); dlqErr != nil {
			// Watermark stays put — without DLQ persistence the next
			// cycle would re-read these rows and re-drive the same push.
			return fmt.Errorf("audit stream: dlq enqueue (push err: %v): %w", pushErr, dlqErr)
		}
	}
	return w.advanceWatermark(ctx, tenantID, maxSeq)
}

func (w *StreamWorker) tenants(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := w.pool.Query(ctx,
		`SELECT tenant_id FROM (
		   SELECT DISTINCT tenant_id FROM audit_logs
		   UNION
		   SELECT tenant_id FROM audit_stream_state
		 ) t ORDER BY tenant_id`,
	)
	if err != nil {
		return nil, fmt.Errorf("audit stream: tenants: %w", err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("audit stream: scan tenant: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit stream: tenant rows: %w", err)
	}
	return out, nil
}

func (w *StreamWorker) readWatermark(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	var last int64
	err := w.pool.QueryRow(ctx,
		`SELECT last_seq FROM audit_stream_state WHERE tenant_id = $1`,
		tenantID,
	).Scan(&last)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	return last, nil
}

func (w *StreamWorker) advanceWatermark(ctx context.Context, tenantID uuid.UUID, newSeq int64) error {
	if _, err := w.pool.Exec(ctx,
		`INSERT INTO audit_stream_state (tenant_id, last_seq, updated_at)
		 VALUES ($1, $2, now())
		 ON CONFLICT (tenant_id) DO UPDATE
		   SET last_seq = GREATEST(audit_stream_state.last_seq, EXCLUDED.last_seq),
		       updated_at = now()`,
		tenantID, newSeq,
	); err != nil {
		return fmt.Errorf("audit stream: advance watermark: %w", err)
	}
	return nil
}

func (w *StreamWorker) fetchEvent(ctx context.Context, tenantID uuid.UUID, seq int64) (stream.Event, error) {
	row := w.pool.QueryRow(ctx,
		`SELECT id, tenant_id, sequence_no, event_type, event_timestamp, outcome, reason_code,
		        actor_type, actor_id, actor_session_id, target_type, target_id,
		        source_service, client_ip_coarse, client_geo_coarse, client_ua_family,
		        request_id, correlation_id, retention_bucket, metadata
		   FROM audit_logs
		  WHERE tenant_id = $1 AND sequence_no = $2`,
		tenantID, seq,
	)
	return scanEvent(row)
}

// scanRow is the shared shape between QueryRow and Query.Next results so
// scanEvent can take either.
type scanRow interface {
	Scan(dest ...any) error
}

func scanEvent(r scanRow) (stream.Event, error) {
	var (
		e               stream.Event
		reasonCode      *string
		actorID         *uuid.UUID
		actorSessionID  *uuid.UUID
		targetType      *string
		targetID        *string
		clientIPCoarse  *string
		clientGeoCoarse *string
		clientUAFamily  *string
		requestID       *string
		correlationID   *uuid.UUID
		metadataBytes   []byte
	)
	if err := r.Scan(
		&e.ID, &e.TenantID, &e.SequenceNo, &e.EventType, &e.EventTimestamp, &e.Outcome, &reasonCode,
		&e.ActorType, &actorID, &actorSessionID, &targetType, &targetID,
		&e.SourceService, &clientIPCoarse, &clientGeoCoarse, &clientUAFamily,
		&requestID, &correlationID, &e.RetentionBucket, &metadataBytes,
	); err != nil {
		return stream.Event{}, err
	}
	e.ReasonCode = reasonCode
	e.ActorID = actorID
	e.ActorSessionID = actorSessionID
	e.TargetType = targetType
	e.TargetID = targetID
	e.ClientIPCoarse = clientIPCoarse
	e.ClientGeoCoarse = clientGeoCoarse
	e.ClientUAFamily = clientUAFamily
	e.RequestID = requestID
	e.CorrelationID = correlationID
	if len(metadataBytes) > 0 {
		_ = json.Unmarshal(metadataBytes, &e.Metadata)
	}
	return e, nil
}

// markDroppedAndAudit atomically (a) writes the audit.stream.dropped
// audit-of-audit row and (b) flips the DLQ row to attempt_count=-1.
// Both run in the same tx so a partial outcome — DLQ marked dropped
// but no corresponding audit row, or vice versa — is impossible. On
// commit failure the row stays retryable; the next cycle re-detects
// the age and re-attempts the drop.
func (w *StreamWorker) markDroppedAndAudit(ctx context.Context, r stream.DLQRow) error {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("audit stream: begin dropped: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := w.auditStore.Emit(ctx, tx, Event{
		EventType:     "audit.stream.dropped",
		ActorType:     ActorTypeSystem,
		TenantID:      r.TenantID,
		SourceService: "audit",
		TargetType:    "audit_log",
		TargetID:      fmt.Sprintf("%s:%d", r.TenantID, r.SequenceNo),
		Outcome:       "failure",
		Metadata: map[string]any{
			"audit_id":      r.AuditID.String(),
			"sequence_no":   r.SequenceNo,
			"attempt_count": r.AttemptCount,
			"last_error":    truncate(r.LastError, 256),
			"backend":       w.backend,
		},
	}); err != nil {
		return fmt.Errorf("audit stream: emit dropped: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE audit_stream_dlq
		    SET attempt_count = -1,
		        next_retry_at = NULL
		  WHERE tenant_id = $1 AND sequence_no = $2`,
		r.TenantID, r.SequenceNo,
	); err != nil {
		return fmt.Errorf("audit stream: mark dropped: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("audit stream: commit dropped: %w", err)
	}
	slog.Error("audit stream: dropped after max retries",
		"tenant_id", r.TenantID,
		"sequence_no", r.SequenceNo,
		"backend", w.backend,
		"last_error", r.LastError,
	)
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func buildStreamer(ctx context.Context, cfg *instanceconfig.Service, pool *pgxpool.Pool, backend string) (stream.Streamer, error) {
	endpoint, err := cfg.AuditStreamEndpoint(ctx, pool)
	if err != nil {
		return nil, fmt.Errorf("audit stream: read endpoint: %w", err)
	}
	if endpoint == "" {
		return nil, fmt.Errorf("audit stream: endpoint empty for backend %q", backend)
	}
	switch backend {
	case "syslog":
		// nil tlsCfg → NewSyslogStreamer fills in ServerName from the
		// endpoint host + MinVersion TLS 1.2. Operators wanting pinned
		// CAs or mTLS will need a future config knob.
		return stream.NewSyslogStreamer(endpoint, nil)
	case "otlp":
		token, err := cfg.AuditStreamTokenRef(ctx, pool)
		if err != nil {
			return nil, fmt.Errorf("audit stream: read token: %w", err)
		}
		return stream.NewOTLPStreamer(endpoint, token)
	default:
		return nil, fmt.Errorf("audit stream: unknown backend %q", backend)
	}
}
