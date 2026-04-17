package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPostLogin_MfaRequired_NotEnrolled_Returns202Enroll(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	// mfa_required defaults to true.

	body, _ := json.Marshal(map[string]string{"email": "admin@example.com", "password": "CorrectHorse1Battery"})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d: %s", rec.Code, rec.Body.String())
	}

	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["totp_enrollment_required"] != true {
		t.Fatalf("want totp_enrollment_required=true, got %v", out)
	}

	// Enroll token cookie set.
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "schlass_mfa_enroll" {
			cookie = c
			break
		}
	}
	if cookie == nil || cookie.Value == "" {
		t.Fatal("no schlass_mfa_enroll cookie set")
	}
}

func TestPostLogin_MfaRequired_Enrolled_Returns202Challenge(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	// Uses the enrollment helper from mfa_challenge_test.go to get the admin
	// fully enrolled.
	enrollTestUser(t, env, "admin@example.com", "CorrectHorse1Battery")

	body, _ := json.Marshal(map[string]string{"email": "admin@example.com", "password": "CorrectHorse1Battery"})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d: %s", rec.Code, rec.Body.String())
	}

	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["totp_required"] != true {
		t.Fatalf("want totp_required=true, got %v", out)
	}

	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "schlass_mfa_challenge" {
			cookie = c
			break
		}
	}
	if cookie == nil || cookie.Value == "" {
		t.Fatal("no schlass_mfa_challenge cookie set")
	}
}

func TestGetMe_ForceMfaEnrollmentFlag(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	// Temporarily disable MFA so we can log in without enrolling.
	_, err := env.Pool.Exec(t.Context(), `UPDATE instance_config SET value = 'false' WHERE key = 'mfa_required'`)
	if err != nil {
		t.Fatalf("disable mfa: %v", err)
	}
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	// Re-enable MFA so GetMe surfaces force_mfa_enrollment=true.
	_, err = env.Pool.Exec(t.Context(), `UPDATE instance_config SET value = 'true' WHERE key = 'mfa_required'`)
	if err != nil {
		t.Fatalf("re-enable mfa: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/me", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var out struct {
		User struct {
			ForceMFAEnrollment bool `json:"force_mfa_enrollment"`
		} `json:"user"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if !out.User.ForceMFAEnrollment {
		t.Fatal("want force_mfa_enrollment=true on /api/me when user has no TOTP enrolled and mfa_required=true")
	}
}
