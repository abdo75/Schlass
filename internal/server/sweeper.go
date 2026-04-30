package server

// Nightly sweeper — deletes expired password-reset tokens + authorization
// codes. Bound to main ctx so graceful shutdown cancels cleanly.

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/audit"
)

// AuditLogger is audit.Logger — the shared contract used by handlers, oidc,
// and the scheduler. *audit.Store satisfies it.
type AuditLogger = audit.Logger

// StartSweeper runs RunSweepOnce every `interval` until ctx is cancelled.
// interval=0 returns immediately (test / disabled mode).
func StartSweeper(ctx context.Context, pool *pgxpool.Pool, interval time.Duration, auditStore AuditLogger) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := RunSweepOnce(ctx, pool, auditStore); err != nil {
				slog.Error("sweeper: run failed", "error", err)
			}
		}
	}
}

// RunSweepOnce deletes expired rows and writes one audit row summarizing
// the pass. Exported so tests can drive a single iteration synchronously.
//
// Retention:
//   - password_reset_tokens older than 30 days
//   - authorization_codes older than 7 days
func RunSweepOnce(ctx context.Context, pool *pgxpool.Pool, auditStore AuditLogger) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	resetTag, err := tx.Exec(ctx,
		`DELETE FROM password_reset_tokens WHERE expires_at < now() - INTERVAL '30 days'`)
	if err != nil {
		return err
	}
	codeTag, err := tx.Exec(ctx,
		`DELETE FROM authorization_codes WHERE expires_at < now() - INTERVAL '7 days'`)
	if err != nil {
		return err
	}

	if err := auditStore.Emit(ctx, tx, audit.Event{
		EventType:  "password_reset.cleanup_swept",
		ActorEmail: "system:sweeper",
		TargetType: "schedule",
		TargetID:   "sweeper",
		Outcome:    "success",
		Metadata: map[string]any{
			"reset_rows_deleted":     resetTag.RowsAffected(),
			"auth_code_rows_deleted": codeTag.RowsAffected(),
		},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
