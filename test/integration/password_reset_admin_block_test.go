//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestPasswordReset_AdminBlocked_Returns200AndNoTokenRow(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	adminID := env.DirectCreateUser(t, "admin-block@example.com", "super_admin")

	body, _ := json.Marshal(map[string]any{"email": "admin-block@example.com"})
	r := publicPost(t, env, "/api/password-reset/request", body)
	if r.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", r.Code)
	}

	// No token row must be created for a super_admin.
	var n int
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1`, adminID,
	).Scan(&n); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if n != 0 {
		t.Fatalf("admin token rows: want 0, got %d", n)
	}
}

func TestPasswordReset_AdminBlocked_AuditRowPresent(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	adminID := env.DirectCreateUser(t, "admin-audit@example.com", "super_admin")

	body, _ := json.Marshal(map[string]any{"email": "admin-audit@example.com"})
	if r := publicPost(t, env, "/api/password-reset/request", body); r.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", r.Code)
	}

	var (
		actorID    string
		actorEmail string
		outcome    string
		metaJSON   []byte
	)
	// Post-M2 (REQ-AUD-011): actor_email resolves via the live join.
	err := env.Pool.QueryRow(t.Context(), `
		SELECT a.actor_id::text, u.email, a.outcome, a.metadata
		  FROM audit_logs a
		  LEFT JOIN users u ON u.id = a.actor_id
		 WHERE a.event_type = 'password_reset.admin_blocked'
		   AND a.target_id = $1::text
		 ORDER BY a.created_at DESC
		 LIMIT 1
	`, adminID).Scan(&actorID, &actorEmail, &outcome, &metaJSON)
	if err != nil {
		t.Fatalf("audit lookup: %v", err)
	}
	if actorID != adminID.String() {
		t.Fatalf("actor_id: want %s, got %s", adminID, actorID)
	}
	if actorEmail != "admin-audit@example.com" {
		t.Fatalf("actor_email: want admin-audit@example.com, got %q", actorEmail)
	}
	if outcome != "success" {
		t.Fatalf("outcome: want success, got %q", outcome)
	}
	var meta map[string]any
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		t.Fatalf("metadata json: %v", err)
	}
	if meta["reason"] != "super_admin_cannot_self_reset" {
		t.Fatalf("metadata.reason: want super_admin_cannot_self_reset, got %v", meta["reason"])
	}
}

func TestPasswordReset_NonAdmin_FlowUnchanged(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	uid := env.DirectCreateUser(t, "regular@example.com", "user")

	body, _ := json.Marshal(map[string]any{"email": "regular@example.com"})
	if r := publicPost(t, env, "/api/password-reset/request", body); r.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", r.Code)
	}

	var n int
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1`, uid,
	).Scan(&n); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if n != 1 {
		t.Fatalf("non-admin token rows: want 1, got %d", n)
	}
}
