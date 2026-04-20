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
