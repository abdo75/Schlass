package integration

import (
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Seeds a schlass_mfa_enroll token into Valkey directly (bypassing /api/login
// which does not yet emit 202 — that's Task 12) and verifies /start returns
// a fresh secret + provision URI and writes the secret back into the same
// Valkey key.
func TestMfaEnrollmentStart_Isolated(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")

	userID := env.GetUserIDByEmail(t, "admin@example.com")

	token := "test-enroll-token-abc"
	key := "mfa:enroll:" + token
	if err := env.Valkey.HSet(t.Context(), key, "user_id", userID.String()).Err(); err != nil {
		t.Fatalf("HSet user_id: %v", err)
	}
	if err := env.Valkey.Expire(t.Context(), key, 10*60).Err(); err != nil {
		t.Fatalf("Expire: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/start", nil)
	req.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var out struct {
		SecretBase32 string `json:"secret_base32"`
		ProvisionURI string `json:"provision_uri"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.SecretBase32 == "" {
		t.Fatal("empty secret_base32")
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(out.SecretBase32); err != nil {
		t.Fatalf("secret_base32 not valid base32 (unpadded): %v", err)
	}
	if !strings.HasPrefix(out.ProvisionURI, "otpauth://totp/") {
		t.Fatalf("provision_uri missing otpauth prefix: %s", out.ProvisionURI)
	}
	if !strings.Contains(out.ProvisionURI, "secret="+out.SecretBase32) {
		t.Fatal("provision_uri secret doesn't match returned secret_base32")
	}

	stored, err := env.Valkey.HGet(t.Context(), key, "secret_base32").Result()
	if err != nil {
		t.Fatalf("HGet secret_base32: %v", err)
	}
	if stored != out.SecretBase32 {
		t.Fatalf("Valkey secret %q != response secret %q", stored, out.SecretBase32)
	}
}

func TestMfaEnrollmentStart_NoCookie_401(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")

	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/start", nil)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

func TestMfaEnrollmentStart_AlreadyEnrolled_400(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	uid := env.GetUserIDByEmail(t, "admin@example.com")

	// Simulate already-enrolled: set totp_enrolled_at on the user.
	if _, err := env.Pool.Exec(t.Context(),
		`UPDATE users SET totp_enrolled_at = now(), totp_secret_encrypted = '\x00'::bytea WHERE id = $1`,
		uid,
	); err != nil {
		t.Fatalf("seed enrolled: %v", err)
	}

	token := "already-enrolled-token"
	env.Valkey.HSet(t.Context(), "mfa:enroll:"+token, "user_id", uid.String())
	env.Valkey.Expire(t.Context(), "mfa:enroll:"+token, 10*60)

	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/start", nil)
	req.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "MFA_ALREADY_ENROLLED" {
		t.Fatalf("want error=MFA_ALREADY_ENROLLED, got %v", body["error"])
	}
}
