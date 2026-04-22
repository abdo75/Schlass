// Package scheduler runs background goroutines bound to the main context.
// Today: expired-token + expired-auth-code sweeper. Shut down on ctx cancel.
package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/database"
	"github.com/abdo75/Schlass/internal/store"
)

// AuditLogger matches the narrow contract used elsewhere (handler, oidc).
// *store.AuditStore satisfies it.
type AuditLogger interface {
	Log(ctx context.Context, q database.Querier, entry store.AuditEntry) error
}

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

	if err := auditStore.Log(ctx, tx, store.AuditEntry{
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
