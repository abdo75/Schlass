//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// TestMigration011_HardDeleteWithAuditRowsWorks verifies that after migration
// 000011 runs, deleting a user with existing audit rows succeeds — the FK is
// gone, so the delete is not blocked. The audit rows persist and still point
// at the now-deleted user's id (dangling by design).
func TestMigration011_HardDeleteWithAuditRowsWorks(t *testing.T) {
	ctx := context.Background()
	env := NewTestEnv(t)

	// Seed an admin via the setup wizard (uses the normal code path).
	env.SeedAdmin(t, "victim@example.com", "CorrectHorse42Battery")

	// Find their id
	var victimID uuid.UUID
	if err := env.Pool.QueryRow(ctx,
		`SELECT id FROM users WHERE email = $1`, "victim@example.com",
	).Scan(&victimID); err != nil {
		t.Fatalf("find victim: %v", err)
	}

	// Insert an audit row referencing the victim (simulating past activity).
	// Post-M2 (REQ-AUD-011): no actor_email column; ip_address renamed to
	// client_ip_coarse and stored at /24. Post-M3 (sequence_no NOT NULL,
	// no DEFAULT — see migrations 000005 + 000006): callers that bypass
	// chain.Append must supply sequence_no explicitly.
	if _, err := env.Pool.Exec(ctx, `
		INSERT INTO audit_logs (event_type, actor_id, target_type, target_id, client_ip_coarse, outcome, sequence_no)
		VALUES ('login.succeeded', $1, 'user', $2, '192.0.2.0', 'success',
		        (SELECT COALESCE(MAX(sequence_no), 0) + 1 FROM audit_logs))
	`, victimID, victimID.String()); err != nil {
		t.Fatalf("insert audit row: %v", err)
	}

	// Now delete the user directly via SQL — this would fail with a FK
	// violation before migration 000011, and succeed after.
	if _, err := env.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, victimID); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	// Verify the audit row survived.
	var count int
	if err := env.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_logs WHERE actor_id = $1`, victimID,
	).Scan(&count); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 audit row to survive user deletion, got %d", count)
	}

	// Verify the user row is actually gone.
	var userCount int
	if err := env.Pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE id = $1`, victimID,
	).Scan(&userCount); err != nil {
		t.Fatalf("count user rows: %v", err)
	}
	if userCount != 0 {
		t.Fatalf("expected user row gone, got %d", userCount)
	}
}
