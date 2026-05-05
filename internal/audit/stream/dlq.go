package stream

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DLQRow is one entry in audit_stream_dlq.
type DLQRow struct {
	AuditID      uuid.UUID
	TenantID     uuid.UUID
	SequenceNo   int64
	AttemptCount int32
	LastError    string
	NextRetryAt  *time.Time
	CreatedAt    time.Time
}

// DLQ wraps DB access to audit_stream_dlq. Stateless; safe to share.
type DLQ struct{ Pool *pgxpool.Pool }

// NewDLQ binds a pool to the DAO.
func NewDLQ(pool *pgxpool.Pool) *DLQ { return &DLQ{Pool: pool} }

// PendingEntry is the input shape for Enqueue.
type PendingEntry struct {
	AuditID    uuid.UUID
	TenantID   uuid.UUID
	SequenceNo int64
}

// Enqueue inserts a freshly-failed batch into the DLQ with attempt_count=1
// and next_retry_at=now+Backoff(1). If a row already exists for
// (tenant_id, sequence_no) — a concurrent worker is already retrying it —
// the insert is a no-op via ON CONFLICT.
//
// Single multi-row INSERT (one round-trip) instead of a per-row loop:
// at batch_size = 1000 this is 1 RTT vs 1000 RTTs.
func (d *DLQ) Enqueue(ctx context.Context, entries []PendingEntry, lastError string) error {
	if len(entries) == 0 {
		return nil
	}
	nextRetry := time.Now().Add(Backoff(1))
	errMsg := truncateError(lastError)

	// Build a multi-row VALUES clause + the matching arg slice.
	// attempt_count = 1 (the row has been tried once and failed) is
	// explicit per row; column default in the schema is 0, which is
	// wrong for fresh-failure rows.
	const colsPerRow = 6
	args := make([]any, 0, colsPerRow*len(entries))
	var values strings.Builder
	for i, e := range entries {
		if i > 0 {
			values.WriteByte(',')
		}
		fmt.Fprintf(&values, "($%d,$%d,$%d,$%d,$%d,$%d)",
			colsPerRow*i+1, colsPerRow*i+2, colsPerRow*i+3, colsPerRow*i+4, colsPerRow*i+5, colsPerRow*i+6,
		)
		args = append(args, e.AuditID, e.TenantID, e.SequenceNo, 1, errMsg, nextRetry)
	}
	stmt := `INSERT INTO audit_stream_dlq
	           (audit_id, tenant_id, sequence_no, attempt_count, last_error, next_retry_at)
	         VALUES ` + values.String() + `
	         ON CONFLICT (tenant_id, sequence_no) DO NOTHING`
	if _, err := d.Pool.Exec(ctx, stmt, args...); err != nil {
		return fmt.Errorf("audit dlq: insert: %w", err)
	}
	return nil
}

// ListDue returns DLQ rows for a tenant whose retry window has expired,
// in sequence order. Capped at limit. Permanently-dropped rows
// (attempt_count = -1) are excluded.
func (d *DLQ) ListDue(ctx context.Context, tenantID uuid.UUID, limit int) ([]DLQRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := d.Pool.Query(ctx,
		`SELECT audit_id, tenant_id, sequence_no, attempt_count,
		        COALESCE(last_error, ''), next_retry_at, created_at
		   FROM audit_stream_dlq
		  WHERE tenant_id = $1
		    AND attempt_count >= 0
		    AND (next_retry_at IS NULL OR next_retry_at <= now())
		  ORDER BY sequence_no
		  LIMIT $2`,
		tenantID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("audit dlq: list due: %w", err)
	}
	defer rows.Close()
	var out []DLQRow
	for rows.Next() {
		var r DLQRow
		if err := rows.Scan(&r.AuditID, &r.TenantID, &r.SequenceNo,
			&r.AttemptCount, &r.LastError, &r.NextRetryAt, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("audit dlq: scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit dlq: rows: %w", err)
	}
	return out, nil
}

// Delete removes a row after a successful retry push.
func (d *DLQ) Delete(ctx context.Context, tenantID uuid.UUID, sequenceNo int64) error {
	if _, err := d.Pool.Exec(ctx,
		`DELETE FROM audit_stream_dlq
		  WHERE tenant_id = $1 AND sequence_no = $2`,
		tenantID, sequenceNo,
	); err != nil {
		return fmt.Errorf("audit dlq: delete: %w", err)
	}
	return nil
}

// BumpFailure increments attempt_count, schedules the next retry per
// the backoff curve, and stores a truncated error message. Read+update
// run under FOR UPDATE so a concurrent retry on the same DLQ row can
// not corrupt the backoff alignment.
func (d *DLQ) BumpFailure(ctx context.Context, tenantID uuid.UUID, sequenceNo int64, lastError string) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("audit dlq: begin bump: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var current int32
	if err := tx.QueryRow(ctx,
		`SELECT attempt_count FROM audit_stream_dlq
		  WHERE tenant_id = $1 AND sequence_no = $2
		  FOR UPDATE`,
		tenantID, sequenceNo,
	).Scan(&current); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("audit dlq: bump failure: row gone")
		}
		return fmt.Errorf("audit dlq: read for bump: %w", err)
	}
	nextRetry := time.Now().Add(Backoff(int(current) + 1))
	if _, err := tx.Exec(ctx,
		`UPDATE audit_stream_dlq
		    SET attempt_count = $3,
		        last_error    = $4,
		        next_retry_at = $5
		  WHERE tenant_id = $1 AND sequence_no = $2`,
		tenantID, sequenceNo, current+1, truncateError(lastError), nextRetry,
	); err != nil {
		return fmt.Errorf("audit dlq: bump update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("audit dlq: commit bump: %w", err)
	}
	return nil
}

// CountActive returns the number of DLQ rows still being retried —
// fed into the audit_stream_dlq_size gauge on each scrape.
func (d *DLQ) CountActive(ctx context.Context) (int64, error) {
	var n int64
	if err := d.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_stream_dlq WHERE attempt_count >= 0`,
	).Scan(&n); err != nil {
		return 0, fmt.Errorf("audit dlq: count active: %w", err)
	}
	return n, nil
}

// truncateError caps last_error to 1024 chars so a runaway upstream
// error message can't blow up the DLQ table.
func truncateError(s string) string {
	const limit = 1024
	if len(s) <= limit {
		return s
	}
	return s[:limit]
}
