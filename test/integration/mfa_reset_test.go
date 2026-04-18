//go:build integration

package integration

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminResetMfa_ClearsEnrollmentAndRecoveryCodes(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	// Enroll the initial admin.
	enrollAndCaptureRecoveryCodes(t, env, "admin@example.com", "CorrectHorse1Battery")

	// Create a second super_admin who will do the reset (self-op is forbidden).
	secondAdminID := env.DirectCreateUser(t, "super@example.com", "super_admin")
	secondAdminCookie := env.DirectCreateSession(t, secondAdminID)

	// Capture the first admin's user ID as the reset target.
	targetUID := env.GetUserIDByEmail(t, "admin@example.com")

	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/users/"+targetUID.String()+"/reset-mfa", nil)
	req.AddCookie(secondAdminCookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	u, err := env.UserStore.GetByID(t.Context(), env.Pool, targetUID)
	if err != nil {
		t.Fatalf("GetByID after reset: %v", err)
	}
	if u.TOTPEnrolledAt != nil {
		t.Fatal("totp_enrolled_at should be null after reset")
	}
	if len(u.TOTPSecretEncrypted) != 0 {
		t.Fatal("totp_secret_encrypted should be empty after reset")
	}
	if u.LastUsedTOTPCounter != 0 {
		t.Fatal("last_used_totp_counter should be 0 after reset")
	}
	n, _ := env.RecoveryCodeStore.CountUnused(t.Context(), env.Pool, targetUID)
	if n != 0 {
		t.Fatalf("want 0 recovery codes, got %d", n)
	}

	var ev string
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT event_type FROM audit_logs WHERE event_type = 'mfa.reset' ORDER BY created_at DESC LIMIT 1`,
	).Scan(&ev); err != nil {
		t.Fatalf("scan mfa.reset audit row: %v", err)
	}
	if ev != "mfa.reset" {
		t.Fatal("mfa.reset audit row missing")
	}
}

func TestAdminResetMfa_SelfRejected(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	enrollAndCaptureRecoveryCodes(t, env, "admin@example.com", "CorrectHorse1Battery")

	uid := env.GetUserIDByEmail(t, "admin@example.com")
	cookie := env.DirectCreateSession(t, uid)

	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/users/"+uid.String()+"/reset-mfa", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 (self-op), got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminResetMfa_NotEnrolled_400(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")

	// Create a second user (not enrolled in MFA).
	secondUID := env.DirectCreateUser(t, "user@example.com", "user")

	// Admin does the reset.
	adminUID := env.GetUserIDByEmail(t, "admin@example.com")
	adminCookie := env.DirectCreateSession(t, adminUID)

	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/users/"+secondUID.String()+"/reset-mfa", nil)
	req.AddCookie(adminCookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 (MFA_NOT_ENROLLED), got %d: %s", rec.Code, rec.Body.String())
	}
}
