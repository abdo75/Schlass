//go:build integration

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

func TestPostLogin_ForcePasswordChange_PrecedesMfa(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	// Setup the initial admin (no force_password_change by default).
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")

	// Disable MFA to create the target user cleanly via the API.
	_, err := env.Pool.Exec(t.Context(), `UPDATE instance_config SET value = 'false' WHERE key = 'mfa_required'`)
	if err != nil {
		t.Fatalf("disable mfa: %v", err)
	}

	// Admin logs in and creates a new user — user gets a temp password + force_password_change=true.
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	createBody, _ := json.Marshal(map[string]string{"email": "newuser@example.com", "role": "user"})
	createReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/users", bytes.NewReader(createBody))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Origin", "http://localhost:3000")
	createReq.AddCookie(adminCookie)
	createRec := httptest.NewRecorder()
	env.Router.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create user failed: %d %s", createRec.Code, createRec.Body.String())
	}
	var createResp struct {
		TemporaryPassword string `json:"temporary_password"`
	}
	if err := json.NewDecoder(createRec.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode create-user response: %v", err)
	}
	tempPassword := createResp.TemporaryPassword
	if tempPassword == "" {
		t.Fatal("no temporary_password in create-user response")
	}

	// Re-enable MFA so the new user is under mfa_required.
	_, err = env.Pool.Exec(t.Context(), `UPDATE instance_config SET value = 'true' WHERE key = 'mfa_required'`)
	if err != nil {
		t.Fatalf("re-enable mfa: %v", err)
	}

	// New user logs in with the temp password while mfa_required=true.
	loginBody, _ := json.Marshal(map[string]string{"email": "newuser@example.com", "password": tempPassword})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)

	// KEY ASSERTION: force_password_change takes precedence over MFA.
	// The response must be 200 (session issued), NOT 202 (enrollment required).
	if rec.Code != http.StatusOK {
		t.Fatalf("force_password_change user should get 200 (session+change-password path), got %d: %s",
			rec.Code, rec.Body.String())
	}

	// A session cookie must be set.
	var session *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "schlass_session" {
			session = c
		}
	}
	if session == nil || session.Value == "" {
		t.Fatal("no session cookie on force_password_change login")
	}

	// No enrollment cookie should be set — we haven't entered that flow yet.
	for _, c := range rec.Result().Cookies() {
		if c.Name == "schlass_mfa_enroll" && c.Value != "" {
			t.Fatal("enrollment cookie should NOT be set when force_password_change takes precedence")
		}
	}

	// Confirm the audit row carries force_password_change_pending=true.
	// Post-M2 (REQ-AUD-011): actor_email is gone; resolve via the join.
	var metadata []byte
	_ = env.Pool.QueryRow(t.Context(),
		`SELECT a.metadata FROM audit_logs a
		   JOIN users u ON u.id = a.actor_id
		  WHERE a.event_type = 'login.succeeded' AND u.email = 'newuser@example.com'`,
	).Scan(&metadata)
	if len(metadata) == 0 {
		t.Fatal("expected a login.succeeded audit row for newuser@example.com")
	}
	var meta map[string]any
	if err := json.Unmarshal(metadata, &meta); err != nil {
		t.Fatalf("unmarshal audit metadata: %v", err)
	}
	if meta["force_password_change_pending"] != true {
		t.Errorf("expected force_password_change_pending=true in audit metadata, got %v", meta)
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
