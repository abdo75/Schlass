//go:build integration

package integration

import (
	"context"
	"testing"
)

func TestRLSPreventsAuditLogDeletion(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	_, err := env.Pool.Exec(ctx,
		`INSERT INTO audit_logs (event_type, actor_email, outcome)
		 VALUES ('test.event', 'test@test.com', 'success')`,
	)
	if err != nil {
		t.Fatalf("failed to insert audit log: %v", err)
	}

	var count int
	err = env.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs").Scan(&count)
	if err != nil {
		t.Fatalf("failed to count audit logs: %v", err)
	}
	if count == 0 {
		t.Fatal("expected at least one audit log entry")
	}

	_, err = env.Pool.Exec(ctx, "DELETE FROM audit_logs")
	if err == nil {
		t.Fatal("expected DELETE on audit_logs to fail for app role, but it succeeded")
	}

	_, err = env.Pool.Exec(ctx, "UPDATE audit_logs SET outcome = 'failure'")
	if err == nil {
		t.Fatal("expected UPDATE on audit_logs to fail for app role, but it succeeded")
	}

	err = env.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs").Scan(&count)
	if err != nil {
		t.Fatalf("failed to count audit logs after attempted delete: %v", err)
	}
	if count == 0 {
		t.Fatal("audit logs were deleted despite RLS — tamper protection failed")
	}
}

func TestRLSAllowsAuditLogInsertAndSelect(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	_, err := env.Pool.Exec(ctx,
		`INSERT INTO audit_logs (event_type, actor_email, outcome)
		 VALUES ('test.insert', 'test@test.com', 'success')`,
	)
	if err != nil {
		t.Fatalf("INSERT should succeed for app role: %v", err)
	}

	var eventType string
	err = env.Pool.QueryRow(ctx,
		"SELECT event_type FROM audit_logs WHERE event_type = 'test.insert'",
	).Scan(&eventType)
	if err != nil {
		t.Fatalf("SELECT should succeed for app role: %v", err)
	}
	if eventType != "test.insert" {
		t.Fatalf("expected event_type=test.insert, got %s", eventType)
	}
}
