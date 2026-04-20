//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// publicPost fires a POST against the test router with no auth cookie and
// an application/json body. Used for endpoints that are deliberately
// unauthenticated (e.g. the password-reset request).
func publicPost(t *testing.T, env *TestEnv, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	return rec
}

func TestPasswordResetRequest_MatchedEmail_Inserts(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	userID := env.DirectCreateUser(t, "reset-me@example.com", "user")

	body, _ := json.Marshal(map[string]any{"email": "reset-me@example.com"})
	resp := publicPost(t, env, "/api/password-reset/request", body)
	if resp.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", resp.Code, resp.Body.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var count int
	if err := env.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1`, userID,
	).Scan(&count); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if count != 1 {
		t.Fatalf("want 1 token row, got %d", count)
	}

	var matched bool
	if err := env.Pool.QueryRow(ctx,
		`SELECT (metadata->>'email_matched')::bool
		 FROM audit_logs
		 WHERE event_type = 'password_reset.requested'
		 ORDER BY created_at DESC LIMIT 1`,
	).Scan(&matched); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if !matched {
		t.Fatal("audit email_matched should be true")
	}
}

func TestPasswordResetRequest_UnknownEmail_200_NoRow(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	body, _ := json.Marshal(map[string]any{"email": "nobody@example.com"})
	resp := publicPost(t, env, "/api/password-reset/request", body)
	if resp.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (enumeration-safe): %s", resp.Code, resp.Body.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var count int
	if err := env.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM password_reset_tokens`,
	).Scan(&count); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if count != 0 {
		t.Fatalf("want 0 tokens, got %d", count)
	}

	var matched bool
	if err := env.Pool.QueryRow(ctx,
		`SELECT (metadata->>'email_matched')::bool
		 FROM audit_logs
		 WHERE event_type = 'password_reset.requested'
		 ORDER BY created_at DESC LIMIT 1`,
	).Scan(&matched); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if matched {
		t.Fatal("audit email_matched should be false")
	}
}

func TestPasswordResetRequest_InvalidEmail_200(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	body, _ := json.Marshal(map[string]any{"email": "not-an-email"})
	resp := publicPost(t, env, "/api/password-reset/request", body)
	if resp.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (uniform outer shape): %s", resp.Code, resp.Body.String())
	}
}

// TestPasswordResetConfirm_ValidToken_UpdatesPassword verifies the happy
// path: token row is marked used, audit row present, and revoke_before is
// written to Valkey post-commit (mirrors admin reset-password so OIDC
// tokens + web sessions issued before the reset are invalidated).
func TestPasswordResetConfirm_ValidToken_UpdatesPassword(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	userID := env.DirectCreateUser(t, "confirm-me@example.com", "user")
	token := env.InsertResetToken(t, userID, 30*time.Minute)

	body, _ := json.Marshal(map[string]any{"token": token, "password": "NewStrongPass1!"})
	resp := publicPost(t, env, "/api/password-reset/confirm", body)
	if resp.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", resp.Code, resp.Body.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Token row marked used.
	var usedAt *time.Time
	if err := env.Pool.QueryRow(ctx,
		`SELECT used_at FROM password_reset_tokens WHERE user_id = $1`, userID,
	).Scan(&usedAt); err != nil {
		t.Fatalf("query used_at: %v", err)
	}
	if usedAt == nil {
		t.Fatal("token not marked used")
	}

	// revoke_before key set in Valkey.
	rb, err := env.Valkey.Get(ctx, "user:revoke_before:"+userID.String()).Result()
	if err != nil || rb == "" {
		t.Fatalf("revoke_before not set in Valkey: rb=%q err=%v", rb, err)
	}

	// password_reset.completed audit row present.
	var count int
	if err := env.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM audit_logs WHERE event_type = 'password_reset.completed' AND actor_id = $1`,
		userID,
	).Scan(&count); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if count != 1 {
		t.Fatalf("want 1 completed audit, got %d", count)
	}

	// user.revoke_before_set audit row present (audit-in-tx invariant —
	// every caller that bumps user:revoke_before writes this row in the
	// same tx so the revoke-before event stream is complete).
	var revokeBeforeCount int
	if err := env.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM audit_logs
		 WHERE event_type = 'user.revoke_before_set'
		   AND actor_id = $1
		   AND metadata->>'reason' = 'self_password_reset'`,
		userID,
	).Scan(&revokeBeforeCount); err != nil {
		t.Fatalf("count revoke_before_set audit: %v", err)
	}
	if revokeBeforeCount != 1 {
		t.Fatalf("want 1 user.revoke_before_set audit with reason=self_password_reset, got %d", revokeBeforeCount)
	}
}

func TestPasswordResetConfirm_ExpiredToken_400(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	userID := env.DirectCreateUser(t, "expired@example.com", "user")
	// TTL = -1 minute → token pre-expired.
	token := env.InsertResetToken(t, userID, -1*time.Minute)

	body, _ := json.Marshal(map[string]any{"token": token, "password": "NewStrongPass1!"})
	resp := publicPost(t, env, "/api/password-reset/confirm", body)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", resp.Code)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["error"] != "INVALID_TOKEN" {
		t.Fatalf("error = %q, want INVALID_TOKEN", out["error"])
	}
}

// TestPasswordResetConfirm_ReusedToken_400 asserts single-use semantics: a
// second POST with the same plaintext token after a successful first use
// returns INVALID_TOKEN (used_at != nil branch on GetByTokenForUpdate).
func TestPasswordResetConfirm_ReusedToken_400(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	userID := env.DirectCreateUser(t, "reuse@example.com", "user")
	token := env.InsertResetToken(t, userID, 30*time.Minute)

	body, _ := json.Marshal(map[string]any{"token": token, "password": "NewStrongPass1!"})
	resp1 := publicPost(t, env, "/api/password-reset/confirm", body)
	if resp1.Code != http.StatusOK {
		t.Fatalf("first: got %d, want 200: %s", resp1.Code, resp1.Body.String())
	}

	// Replay — same token, new password attempt.
	body2, _ := json.Marshal(map[string]any{"token": token, "password": "AnotherPass2!"})
	resp2 := publicPost(t, env, "/api/password-reset/confirm", body2)
	if resp2.Code != http.StatusBadRequest {
		t.Fatalf("replay: got %d, want 400", resp2.Code)
	}
	var out map[string]any
	_ = json.NewDecoder(resp2.Body).Decode(&out)
	if out["error"] != "INVALID_TOKEN" {
		t.Fatalf("error = %q, want INVALID_TOKEN", out["error"])
	}
}

func TestPasswordResetConfirm_WeakPassword_400(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	userID := env.DirectCreateUser(t, "weak@example.com", "user")
	token := env.InsertResetToken(t, userID, 30*time.Minute)

	body, _ := json.Marshal(map[string]any{"token": token, "password": "short"})
	resp := publicPost(t, env, "/api/password-reset/confirm", body)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", resp.Code)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["error"] != "PASSWORD_POLICY_VIOLATION" {
		t.Fatalf("error = %q, want PASSWORD_POLICY_VIOLATION", out["error"])
	}
}

func TestPasswordResetConfirm_UnknownToken_400(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	body, _ := json.Marshal(map[string]any{"token": "obviously-not-a-real-token-xxx", "password": "NewStrongPass1!"})
	resp := publicPost(t, env, "/api/password-reset/confirm", body)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", resp.Code)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["error"] != "INVALID_TOKEN" {
		t.Fatalf("error = %q, want INVALID_TOKEN", out["error"])
	}
}
