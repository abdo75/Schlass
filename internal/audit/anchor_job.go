// Anchor job periodically submits each tenant's current audit chain head to
// the configured immutable backend and records the returned proof reference.
package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/audit/anchor"
	"github.com/abdo75/Schlass/internal/instanceconfig"
)

type AnchorJob struct {
	pool          *pgxpool.Pool
	cfg           *instanceconfig.Service
	auditStore    Logger
	anchorFactory func(context.Context, string, string, string) (anchor.Anchor, error)
}

const defaultHotRetentionDays = 365

func NewAnchorJob(pool *pgxpool.Pool, cfg *instanceconfig.Service, auditStore Logger) *AnchorJob {
	return &AnchorJob{
		pool:          pool,
		cfg:           cfg,
		auditStore:    auditStore,
		anchorFactory: defaultAnchorFactory,
	}
}

func StartAnchorJob(ctx context.Context, pool *pgxpool.Pool, cfg *instanceconfig.Service, auditStore Logger) {
	job := NewAnchorJob(pool, cfg, auditStore)
	interval, err := cfg.AuditAnchorIntervalSecs(ctx, pool)
	if err != nil {
		slog.Warn("audit anchor: failed to read interval, falling back to default", "error", err)
		interval = 3600
	}
	if interval <= 0 {
		interval = 3600
	}
	// tickEvery is the polling resolution. Actual anchor frequency is gated by
	// dueByEvents and dueByTime inside anchorTenant against audit.anchor.events_per_anchor
	// and audit.anchor.interval_secs. Cap at 1 minute so short interval_secs values
	// don't busy-poll the DB.
	tickEvery := min(time.Duration(interval)*time.Second, time.Minute)
	ticker := time.NewTicker(tickEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := job.RunOnce(ctx); err != nil {
				slog.Error("audit anchor: run failed", "error", err)
			}
		}
	}
}

func (j *AnchorJob) RunOnce(ctx context.Context) error {
	backend, err := j.cfg.AuditAnchorBackend(ctx, j.pool)
	if err != nil {
		slog.Warn("audit anchor: failed to read backend, falling back to none", "error", err)
		backend = anchor.NoneBackend
	}
	if backend == anchor.NoneBackend {
		slog.Debug("audit anchor: backend none, skipping")
		return nil
	}
	bucket, err := j.cfg.AuditAnchorBucket(ctx, j.pool)
	if err != nil {
		return fmt.Errorf("audit anchor: read bucket: %w", err)
	}
	path, err := j.cfg.AuditAnchorPath(ctx, j.pool)
	if err != nil {
		return fmt.Errorf("audit anchor: read path: %w", err)
	}
	eventsPerAnchor, err := j.cfg.AuditAnchorEventsPerAnchor(ctx, j.pool)
	if err != nil {
		slog.Warn("audit anchor: failed to read events_per_anchor, falling back to default", "error", err)
		eventsPerAnchor = 10000
	}
	intervalSecs, err := j.cfg.AuditAnchorIntervalSecs(ctx, j.pool)
	if err != nil {
		slog.Warn("audit anchor: failed to read interval_secs, falling back to default", "error", err)
		intervalSecs = 3600
	}
	hotRetentionDays := j.hotRetentionDays(ctx)
	dest, err := j.anchorFactory(ctx, backend, bucket, path)
	if err != nil {
		return err
	}
	if closer, ok := dest.(interface{ Close() error }); ok {
		defer func() {
			if err := closer.Close(); err != nil {
				slog.Warn("audit anchor: close backend", "backend", backend, "error", err)
			}
		}()
	}
	tenants, err := j.tenants(ctx)
	if err != nil {
		return err
	}
	var firstErr error
	for _, tenantID := range tenants {
		if err := j.anchorTenant(ctx, dest, backend, tenantID, eventsPerAnchor, time.Duration(intervalSecs)*time.Second, hotRetentionDays); err != nil {
			slog.Error("audit anchor: tenant failed", "tenant_id", tenantID, "error", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
	}
	return firstErr
}

func (j *AnchorJob) hotRetentionDays(ctx context.Context) int {
	days, err := j.cfg.GetInt(ctx, j.pool, "audit.retention.security_hot_days")
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Warn("audit anchor: failed to read hot retention days, falling back to default", "error", err)
		}
		return defaultHotRetentionDays
	}
	if days <= 0 {
		return defaultHotRetentionDays
	}
	return days
}

func (j *AnchorJob) anchorTenant(ctx context.Context, dest anchor.Anchor, backend string, tenantID uuid.UUID, eventsPerAnchor int, interval time.Duration, hotRetentionDays int) error {
	head, err := (&Chain{}).Head(ctx, j.pool, tenantID)
	if err != nil {
		return err
	}
	if head.SequenceNo == 0 {
		return nil
	}
	lastSeq, lastAt, ok, err := j.lastAnchor(ctx, tenantID)
	if err != nil {
		return err
	}
	if ok && head.SequenceNo <= lastSeq {
		return nil
	}
	dueByEvents := !ok || head.SequenceNo-lastSeq >= int64(eventsPerAnchor)
	dueByTime := ok && time.Since(lastAt) >= interval
	if !dueByEvents && !dueByTime {
		return nil
	}
	head.AnchoredAt = time.Now().UTC()
	head.RetainUntil = head.AnchoredAt.AddDate(0, 0, hotRetentionDays)
	// We Submit to the cloud anchor BEFORE inserting the DB row. This guarantees
	// at-least-once cloud delivery: a transient DB error after a successful Submit
	// causes a retry that re-Submits, producing a duplicate cloud object (S3
	// Object Lock requires versioning, so duplicates are locked siblings, not lost
	// writes). The reverse order would let a successful DB row reference a cloud
	// object that never landed: silent loss of SOC 2 evidence, which is worse.
	proof, err := dest.Submit(ctx, head)
	if err != nil {
		slog.Error("audit anchor: submit failed", "tenant_id", tenantID, "backend", backend, "error", err)
		return err
	}
	if proof.Backend == "" {
		proof.Backend = backend
	}
	inserted, err := j.insertAnchor(ctx, head, proof)
	if err != nil {
		return err
	}
	if inserted {
		return j.emitCreated(ctx, head, proof)
	}
	return nil
}

func (j *AnchorJob) tenants(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := j.pool.Query(ctx, `SELECT DISTINCT tenant_id FROM audit_logs ORDER BY tenant_id`)
	if err != nil {
		return nil, fmt.Errorf("audit anchor: tenants: %w", err)
	}
	defer rows.Close()
	var tenants []uuid.UUID
	for rows.Next() {
		var tenantID uuid.UUID
		if err := rows.Scan(&tenantID); err != nil {
			return nil, fmt.Errorf("audit anchor: scan tenant: %w", err)
		}
		tenants = append(tenants, tenantID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit anchor: tenant rows: %w", err)
	}
	return tenants, nil
}

func (j *AnchorJob) lastAnchor(ctx context.Context, tenantID uuid.UUID) (int64, time.Time, bool, error) {
	var sequenceNo int64
	var anchoredAt time.Time
	err := j.pool.QueryRow(ctx,
		`SELECT sequence_no, anchored_at
		   FROM audit_anchors
		  WHERE tenant_id = $1
		  ORDER BY sequence_no DESC
		  LIMIT 1`,
		tenantID,
	).Scan(&sequenceNo, &anchoredAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, time.Time{}, false, nil
		}
		return 0, time.Time{}, false, fmt.Errorf("audit anchor: last anchor: %w", err)
	}
	return sequenceNo, anchoredAt, true, nil
}

func (j *AnchorJob) insertAnchor(ctx context.Context, head anchor.ChainHead, proof anchor.ProofRef) (bool, error) {
	tx, err := j.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx,
		`INSERT INTO audit_anchors (tenant_id, sequence_no, row_hash, backend, proof_ref, anchored_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (tenant_id, sequence_no) DO NOTHING`,
		head.TenantID, head.SequenceNo, head.RowHash, proof.Backend, proof.Ref, head.AnchoredAt,
	)
	if err != nil {
		return false, fmt.Errorf("audit anchor: insert proof: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("audit anchor: commit proof: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (j *AnchorJob) emitCreated(ctx context.Context, head anchor.ChainHead, proof anchor.ProofRef) error {
	tx, err := j.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := j.auditStore.Emit(ctx, tx, Event{
		EventType:     "audit.anchor.created",
		ActorType:     ActorTypeSystem,
		TenantID:      head.TenantID,
		SourceService: "audit",
		TargetType:    "audit_anchor",
		TargetID:      fmt.Sprintf("%s:%d", head.TenantID, head.SequenceNo),
		Outcome:       "success",
		// proof_ref is intentionally operator-visible in the audit event metadata.
		// It points at the anchor backend (file path with offset, S3 URI, or GCS URI)
		// so operators can verify the anchor independently. It contains no PII.
		Metadata: map[string]any{
			"tenant_id":   head.TenantID.String(),
			"sequence_no": head.SequenceNo,
			"backend":     proof.Backend,
			"proof_ref":   proof.Ref,
		},
	}); err != nil {
		return fmt.Errorf("audit anchor: emit created: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("audit anchor: commit created: %w", err)
	}
	return nil
}

func defaultAnchorFactory(ctx context.Context, backend, bucket, path string) (anchor.Anchor, error) {
	switch backend {
	case anchor.NoneBackend:
		return anchor.Noop{}, nil
	case anchor.AppendFileBackend:
		return anchor.NewAppendFile(path), nil
	case anchor.S3Backend:
		return anchor.NewS3FromDefaultConfig(ctx, bucket, 365)
	case anchor.GCSBackend:
		return anchor.NewGCSFromDefaultConfig(ctx, bucket)
	default:
		return nil, fmt.Errorf("audit anchor: unknown backend %q", backend)
	}
}
