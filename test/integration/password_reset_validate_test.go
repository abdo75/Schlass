//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPasswordResetValidate_ValidToken_200Empty(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	uid := env.DirectCreateUser(t, "valid@example.com", "user")
	tok := env.InsertResetToken(t, uid, 30*time.Minute)

	body, _ := json.Marshal(map[string]any{"token": tok})
	resp := publicPost(t, env, "/api/password-reset/validate", body)
	if resp.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", resp.Code, resp.Body.String())
	}
	if b := resp.Body.String(); b != "{}\n" && b != "{}" {
		t.Fatalf("body = %q, want empty object", b)
	}

	var usedAt *time.Time
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT used_at FROM password_reset_tokens WHERE user_id = $1`, uid,
	).Scan(&usedAt); err != nil {
		t.Fatalf("query used_at: %v", err)
	}
	if usedAt != nil {
		t.Fatal("validate must not mark token used")
	}
}

func TestPasswordResetValidate_ExpiredToken_400(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	uid := env.DirectCreateUser(t, "exp@example.com", "user")
	tok := env.InsertResetToken(t, uid, -1*time.Minute)
	body, _ := json.Marshal(map[string]any{"token": tok})
	resp := publicPost(t, env, "/api/password-reset/validate", body)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", resp.Code)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["error"] != "INVALID_TOKEN" {
		t.Fatalf("error = %q, want INVALID_TOKEN", out["error"])
	}
}

func TestPasswordResetValidate_UsedToken_400(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	uid := env.DirectCreateUser(t, "used@example.com", "user")
	tok := env.InsertResetToken(t, uid, 30*time.Minute)
	confirmBody, _ := json.Marshal(map[string]any{"token": tok, "password": "NewStrongPass1!"})
	if r := publicPost(t, env, "/api/password-reset/confirm", confirmBody); r.Code != http.StatusOK {
		t.Fatalf("confirm setup: %d %s", r.Code, r.Body.String())
	}
	body, _ := json.Marshal(map[string]any{"token": tok})
	resp := publicPost(t, env, "/api/password-reset/validate", body)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400 for used token", resp.Code)
	}
}

func TestPasswordResetValidate_UnknownToken_400(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	body, _ := json.Marshal(map[string]any{"token": "no-such-token-xxx"})
	resp := publicPost(t, env, "/api/password-reset/validate", body)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", resp.Code)
	}
}

func TestPasswordResetValidate_EmptyToken_400(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	body, _ := json.Marshal(map[string]any{"token": ""})
	resp := publicPost(t, env, "/api/password-reset/validate", body)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", resp.Code)
	}
}

func TestPasswordResetRequest_ReturnsJSONEmptyBody(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	body, _ := json.Marshal(map[string]any{"email": "anyone@example.com"})
	resp := publicPost(t, env, "/api/password-reset/request", body)
	if resp.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.Code)
	}
	ct := resp.Header().Get("Content-Type")
	if ct == "" || !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
}
