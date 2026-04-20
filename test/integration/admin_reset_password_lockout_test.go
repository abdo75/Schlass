//go:build integration

package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAdminResetPassword_ClearsLockout(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "AdminPass12345!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "AdminPass12345!")

	target := env.DirectCreateUser(t, "target@example.com", "user")
	if _, err := env.Pool.Exec(t.Context(), `
		UPDATE users SET failed_login_attempts = 5, locked_until = now() + interval '15 minutes'
		WHERE id = $1
	`, target); err != nil {
		t.Fatalf("seed lockout: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/users/"+target.String()+"/reset-password", bytes.NewReader(nil))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body.String())
	}

	var attempts int
	var lockedUntil *time.Time
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT failed_login_attempts, locked_until FROM users WHERE id = $1`, target,
	).Scan(&attempts, &lockedUntil); err != nil {
		t.Fatalf("query: %v", err)
	}
	if attempts != 0 || lockedUntil != nil {
		t.Fatalf("lockout not cleared: attempts=%d locked_until=%v", attempts, lockedUntil)
	}
}
