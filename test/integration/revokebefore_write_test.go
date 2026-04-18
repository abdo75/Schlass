//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// assertRevokeBeforeAuditRow checks that a user.revoke_before_set audit row
// exists for the given targetUserID with the expected reason. Returns the
// audit row's created_at for freshness assertions.
func assertRevokeBeforeAuditRow(t *testing.T, env *TestEnv, targetUserID, expectedReason string) {
	t.Helper()
	var reason string
	err := env.Pool.QueryRow(context.Background(),
		`SELECT metadata->>'reason'
		 FROM audit_logs
		 WHERE event_type = 'user.revoke_before_set'
		   AND target_id = $1
		 ORDER BY created_at DESC
		 LIMIT 1`,
		targetUserID,
	).Scan(&reason)
	if err != nil {
		t.Fatalf("assertRevokeBeforeAuditRow: no user.revoke_before_set row for user %s: %v", targetUserID, err)
	}
	if reason != expectedReason {
		t.Fatalf("revoke_before_set reason: got %q want %q", reason, expectedReason)
	}
}

// assertValkeyRevokeBefore checks that a user:revoke_before:<userID> key exists
// in Valkey and that its value is a recent unix timestamp (within the last 30s).
func assertValkeyRevokeBefore(t *testing.T, env *TestEnv, userID string) {
	t.Helper()
	key := fmt.Sprintf("user:revoke_before:%s", userID)
	val, err := env.ValkeyClient.Get(context.Background(), key).Result()
	if err != nil {
		t.Fatalf("assertValkeyRevokeBefore: key %s missing: %v", key, err)
	}
	var secs int64
	if _, err := fmt.Sscanf(val, "%d", &secs); err != nil {
		t.Fatalf("assertValkeyRevokeBefore: parse value %q: %v", val, err)
	}
	cutoff := time.Unix(secs, 0)
	age := time.Since(cutoff)
	if age > 30*time.Second {
		t.Fatalf("revoke_before cutoff is too old (%v ago); expected a fresh write", age)
	}
}

// adminDisableUser drives POST /api/users/{id}/disable via the admin API.
func adminDisableUser(t *testing.T, env *TestEnv, adminCookie *http.Cookie, targetID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/users/"+targetID+"/disable", nil)
	req.AddCookie(adminCookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	return rec
}

// adminResetPassword drives POST /api/users/{id}/reset-password via the admin API.
func adminResetPassword(t *testing.T, env *TestEnv, adminCookie *http.Cookie, targetID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/users/"+targetID+"/reset-password", nil)
	req.AddCookie(adminCookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	return rec
}

// adminResetMFA drives POST /api/users/{id}/reset-mfa via the admin API.
func adminResetMFA(t *testing.T, env *TestEnv, adminCookie *http.Cookie, targetID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/users/"+targetID+"/reset-mfa", nil)
	req.AddCookie(adminCookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	return rec
}

// TestRevokeBefore_WriteOnDisable asserts that POST /api/users/{id}/disable
// writes a user.revoke_before_set audit row with reason=disable and writes
// the Valkey cutoff key.
func TestRevokeBefore_WriteOnDisable(t *testing.T) {
	env := NewTestEnv(t)

	// Seed admin + target user.
	adminID := env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	targetID := env.DirectCreateUser(t, "target@example.com", "user")
	adminCookie := env.DirectCreateSession(t, adminID)

	rec := adminDisableUser(t, env, adminCookie, targetID.String())
	if rec.Code != http.StatusNoContent {
		t.Fatalf("disable: want 204, got %d: %s", rec.Code, rec.Body.String())
	}

	assertRevokeBeforeAuditRow(t, env, targetID.String(), "disable")
	assertValkeyRevokeBefore(t, env, targetID.String())
}

// TestRevokeBefore_WriteOnResetPassword asserts that POST /api/users/{id}/reset-password
// writes a user.revoke_before_set audit row with reason=password_reset and the
// Valkey cutoff key.
func TestRevokeBefore_WriteOnResetPassword(t *testing.T) {
	env := NewTestEnv(t)

	adminID := env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	targetID := env.DirectCreateUser(t, "target@example.com", "user")
	adminCookie := env.DirectCreateSession(t, adminID)

	rec := adminResetPassword(t, env, adminCookie, targetID.String())
	if rec.Code != http.StatusOK {
		t.Fatalf("reset-password: want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	assertRevokeBeforeAuditRow(t, env, targetID.String(), "password_reset")
	assertValkeyRevokeBefore(t, env, targetID.String())
}

// TestRevokeBefore_WriteOnResetMFA asserts that POST /api/users/{id}/reset-mfa
// writes a user.revoke_before_set audit row with reason=mfa_reset and the
// Valkey cutoff key. The target user must be enrolled in MFA first.
func TestRevokeBefore_WriteOnResetMFA(t *testing.T) {
	env := NewTestEnv(t)

	// enrollTestUser calls CompleteSetup which creates the admin and enrolls MFA.
	targetID, _ := enrollTestUser(t, env, "admin@example.com", "CorrectHorse1Battery")

	// Need a second admin to perform the reset (self-op is rejected).
	secondAdminID := env.DirectCreateUser(t, "admin2@example.com", "super_admin")
	secondAdminCookie := env.DirectCreateSession(t, secondAdminID)

	rec := adminResetMFA(t, env, secondAdminCookie, targetID)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset-mfa: want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	assertRevokeBeforeAuditRow(t, env, targetID, "mfa_reset")
	assertValkeyRevokeBefore(t, env, targetID)
}

// TestRevokeBefore_WriteOnSelfChangePassword asserts that POST /api/change-password
// writes a user.revoke_before_set audit row with reason=self_change_password and
// the Valkey cutoff key.
func TestRevokeBefore_WriteOnSelfChangePassword(t *testing.T) {
	env := NewTestEnv(t)

	userID := env.SeedAdmin(t, "user@example.com", "CorrectHorse42!")
	cookie := env.DirectCreateSession(t, userID)

	body, _ := json.Marshal(map[string]string{
		"current_password": "CorrectHorse42!",
		"new_password":     "NewPasscode99!",
	})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/change-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("change-password: want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	assertRevokeBeforeAuditRow(t, env, userID.String(), "self_change_password")
	assertValkeyRevokeBefore(t, env, userID.String())
}

// TestRevokeBefore_WriteOnSelfDisableMFA asserts that POST /api/me/mfa/disable
// writes a user.revoke_before_set audit row with reason=self_disable_mfa and
// the Valkey cutoff key.
func TestRevokeBefore_WriteOnSelfDisableMFA(t *testing.T) {
	env := NewTestEnv(t)

	// enrollTestUser creates the user via CompleteSetup and enrolls MFA.
	targetID, _ := enrollTestUser(t, env, "admin@example.com", "CorrectHorse1Battery")
	userUUID := env.GetUserIDByEmail(t, "admin@example.com")
	cookie := env.DirectCreateSession(t, userUUID)

	body, _ := json.Marshal(map[string]string{"current_password": "CorrectHorse1Battery"})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/me/mfa/disable", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("me/mfa/disable: want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	assertRevokeBeforeAuditRow(t, env, targetID, "self_disable_mfa")
	assertValkeyRevokeBefore(t, env, targetID)
}
