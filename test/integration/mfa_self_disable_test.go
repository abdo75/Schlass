package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSelfDisableMfa_Happy(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	enrollTestUser(t, env, "admin@example.com", "CorrectHorse1Battery")
	userID := env.GetUserIDByEmail(t, "admin@example.com")
	cookie := env.DirectCreateSession(t, userID)

	body, _ := json.Marshal(map[string]string{"current_password": "CorrectHorse1Battery"})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/me/mfa/disable", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// TOTP state cleared.
	u, err := env.UserStore.GetByID(t.Context(), env.Pool, userID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if u.TOTPEnrolledAt != nil {
		t.Fatal("totp_enrolled_at not cleared")
	}
	if len(u.TOTPSecretEncrypted) != 0 {
		t.Fatal("totp_secret_encrypted not cleared")
	}

	// Recovery codes deleted.
	n, err := env.RecoveryCodeStore.CountUnused(t.Context(), env.Pool, userID)
	if err != nil {
		t.Fatalf("CountUnused: %v", err)
	}
	if n != 0 {
		t.Fatalf("want 0 recovery codes, got %d", n)
	}

	// Audit row present.
	var ev string
	_ = env.Pool.QueryRow(t.Context(),
		`SELECT event_type FROM audit_logs WHERE event_type = 'mfa.self_reset' ORDER BY created_at DESC LIMIT 1`,
	).Scan(&ev)
	if ev != "mfa.self_reset" {
		t.Fatal("mfa.self_reset audit row missing")
	}

	// Session revoked — next authed request fails.
	checkReq := httptest.NewRequestWithContext(t.Context(), "GET", "/api/me", nil)
	checkReq.AddCookie(cookie)
	checkRec := httptest.NewRecorder()
	env.Router.ServeHTTP(checkRec, checkReq)
	if checkRec.Code != http.StatusUnauthorized {
		t.Fatalf("session should be revoked, got %d", checkRec.Code)
	}
}

func TestSelfDisableMfa_WrongPassword(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	enrollTestUser(t, env, "admin@example.com", "CorrectHorse1Battery")
	userID := env.GetUserIDByEmail(t, "admin@example.com")
	cookie := env.DirectCreateSession(t, userID)

	body, _ := json.Marshal(map[string]string{"current_password": "WrongPassword"})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/me/mfa/disable", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}

	// TOTP still enrolled.
	u, err := env.UserStore.GetByID(t.Context(), env.Pool, userID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if u.TOTPEnrolledAt == nil {
		t.Fatal("totp_enrolled_at should still be set after wrong-password disable attempt")
	}
}

func TestSelfDisableMfa_NotEnrolled(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	userID := env.GetUserIDByEmail(t, "admin@example.com")
	cookie := env.DirectCreateSession(t, userID)

	body, _ := json.Marshal(map[string]string{"current_password": "CorrectHorse1Battery"})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/me/mfa/disable", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 MFA_NOT_ENROLLED, got %d: %s", rec.Code, rec.Body.String())
	}
}
