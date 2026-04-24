//go:build integration

package integration

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/server"
)

func TestSweeper_DeletesExpiredResetTokens(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	uid := env.DirectCreateUser(t, "sweep-user@example.com", "user")

	// 3 expired (31 days old), 1 recent.
	for i := 0; i < 3; i++ {
		seedExpiredResetToken(t, env, uid, 31*24*time.Hour)
	}
	seedExpiredResetToken(t, env, uid, 0) // not expired

	if err := server.RunSweepOnce(t.Context(), env.Pool, audit.NewStore()); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	var n int
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1`, uid,
	).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("remaining reset tokens: want 1, got %d", n)
	}
}

func TestSweeper_AuditRowWithCounts(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	uid := env.DirectCreateUser(t, "sweep-audit@example.com", "user")
	seedExpiredResetToken(t, env, uid, 31*24*time.Hour)
	seedExpiredResetToken(t, env, uid, 31*24*time.Hour)

	if err := server.RunSweepOnce(t.Context(), env.Pool, audit.NewStore()); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	var metaJSON []byte
	err := env.Pool.QueryRow(t.Context(), `
		SELECT metadata
		  FROM audit_logs
		 WHERE event_type = 'password_reset.cleanup_swept'
		 ORDER BY created_at DESC
		 LIMIT 1
	`).Scan(&metaJSON)
	if err != nil {
		t.Fatalf("audit row: %v", err)
	}
	var meta map[string]any
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		t.Fatalf("metadata json: %v", err)
	}
	// JSON unmarshal gives float64 for numeric fields.
	if got, _ := meta["reset_rows_deleted"].(float64); got != 2 {
		t.Fatalf("reset_rows_deleted: want 2, got %v", meta["reset_rows_deleted"])
	}
	if _, ok := meta["auth_code_rows_deleted"]; !ok {
		t.Fatal("auth_code_rows_deleted missing from metadata")
	}
}

// seedExpiredResetToken inserts a reset token row with expires_at in the
// past by the given offset. ageAgo=0 produces a currently-valid row.
func seedExpiredResetToken(t *testing.T, env *TestEnv, userID uuid.UUID, ageAgo time.Duration) {
	t.Helper()
	_, err := env.Pool.Exec(t.Context(), `
		INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
		VALUES ($1, decode(md5(random()::text || clock_timestamp()::text), 'hex'), now() - $2::INTERVAL)
	`, userID, ageAgo)
	if err != nil {
		t.Fatalf("seed reset token: %v", err)
	}
}
