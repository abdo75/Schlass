//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/abdo75/Schlass/internal/recovery"
)

func TestRecoveryReset_Succeeds_OnAdminEmail(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	adminID := env.DirectCreateUser(t, "cli-admin@example.com", "super_admin")

	var out bytes.Buffer
	if err := recovery.Execute(t.Context(), env.Pool, env.Cfg, "cli-admin@example.com", &out); err != nil {
		t.Fatalf("execute: %v", err)
	}

	line := out.String()
	if !strings.HasPrefix(line, "Reset URL: ") {
		t.Fatalf("stdout: want 'Reset URL: ...', got %q", line)
	}
	if !strings.Contains(line, "/reset-password/") {
		t.Fatalf("stdout: missing reset-password path: %q", line)
	}

	// Token row present for the admin.
	var n int
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1`, adminID,
	).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("token rows: want 1, got %d", n)
	}

	// Audit row written with the expected shape.
	var actorEmail string
	var metaJSON []byte
	err := env.Pool.QueryRow(t.Context(), `
		SELECT actor_email, metadata
		  FROM audit_logs
		 WHERE event_type = 'password_reset.recovery_issued'
		   AND target_id = $1::text
		 ORDER BY created_at DESC
		 LIMIT 1
	`, adminID).Scan(&actorEmail, &metaJSON)
	if err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if actorEmail != "system:recovery" {
		t.Fatalf("actor_email: want 'system:recovery', got %q", actorEmail)
	}
	var meta map[string]any
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		t.Fatalf("metadata json: %v", err)
	}
	if meta["target_email"] != "cli-admin@example.com" {
		t.Fatalf("metadata.target_email: %v", meta["target_email"])
	}
	if _, ok := meta["token_id"]; !ok {
		t.Fatal("metadata.token_id missing")
	}
}

func TestRecoveryReset_Refuses_OnNonAdminTarget(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	uid := env.DirectCreateUser(t, "cli-user@example.com", "user")

	var out bytes.Buffer
	err := recovery.Execute(t.Context(), env.Pool, env.Cfg, "cli-user@example.com", &out)
	if err == nil {
		t.Fatal("expected error for non-admin target, got nil")
	}
	if !strings.Contains(err.Error(), "not a super_admin") {
		t.Fatalf("error: want contains 'not a super_admin', got %v", err)
	}

	var n int
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1`, uid,
	).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("token rows: want 0, got %d", n)
	}
}

func TestRecoveryReset_Refuses_OnUnknownEmail(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	var out bytes.Buffer
	err := recovery.Execute(t.Context(), env.Pool, env.Cfg, "nobody@example.com", &out)
	if err == nil {
		t.Fatal("expected error for unknown email, got nil")
	}
}
