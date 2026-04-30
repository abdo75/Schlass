//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/users"
)

// TestPermissionDenied_AuditsTheAttempt verifies that NIST 800-53 AU-2 /
// PCI DSS §10.2.4 coverage holds: when an authenticated non-admin user hits
// an admin-gated endpoint, the 403 response is accompanied by an
// `auth.permission_denied` audit row carrying actor, the missing
// permission, and the request method/path.
func TestPermissionDenied_AuditsTheAttempt(t *testing.T) {
	env := NewTestEnv(t)

	// Disable MFA — the "user" role doesn't have MFA enrolled and the login
	// flow short-circuits with totp_enrollment_required otherwise.
	if _, err := env.Pool.Exec(context.Background(),
		`UPDATE instance_config SET value = 'false' WHERE key = 'mfa_required'`,
	); err != nil {
		t.Fatalf("disable mfa: %v", err)
	}

	// Seed a regular (non-admin) user. The "user" role has zero permissions
	// in rolePermissions, so any /api/users call is a guaranteed denial.
	hash, err := crypto.HashPassword("CorrectHorse42!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	us := users.NewStore()
	regularID, err := us.Create(context.Background(), env.Pool, "regular@example.com", hash, "user", false)
	if err != nil {
		t.Fatalf("seed regular user: %v", err)
	}

	// Sign in to get a session cookie.
	cookie := loginAndGetCookie(t, env, "regular@example.com", "CorrectHorse42!")

	// Hit an admin endpoint with that cookie.
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	// Audit row must exist with actor, target_id = the missing permission,
	// outcome = failure, and metadata carrying method+path.
	var (
		actorID    string
		actorEmail string
		targetType string
		targetID   string
		outcome    string
		method     string
		path       string
	)
	err = env.Pool.QueryRow(context.Background(), `
		SELECT actor_id::text,
		       actor_email,
		       target_type,
		       target_id,
		       outcome,
		       metadata->>'method',
		       metadata->>'path'
		FROM audit_logs
		WHERE event_type = 'auth.permission_denied'
		ORDER BY created_at DESC
		LIMIT 1
	`).Scan(&actorID, &actorEmail, &targetType, &targetID, &outcome, &method, &path)
	if err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if actorID != regularID.String() {
		t.Fatalf("actor_id: want %s, got %s", regularID, actorID)
	}
	if actorEmail != "regular@example.com" {
		t.Fatalf("actor_email: want regular@example.com, got %s", actorEmail)
	}
	if targetType != "permission" {
		t.Fatalf("target_type: want permission, got %s", targetType)
	}
	if targetID != "users.list" {
		t.Fatalf("target_id (missing permission): want users.list, got %s", targetID)
	}
	if outcome != "failure" {
		t.Fatalf("outcome: want failure, got %s", outcome)
	}
	if method != http.MethodGet {
		t.Fatalf("method: want GET, got %s", method)
	}
	if path != "/api/users" {
		t.Fatalf("path: want /api/users, got %s", path)
	}
}

// loginAndGetCookie performs POST /api/login and returns the session cookie.
// Mirrors LoginAsAdmin but works for any role and does not toggle mfa_required
// (regular users have no MFA enrolled by default).
func loginAndGetCookie(t *testing.T, env *TestEnv, email, password string) *http.Cookie {
	t.Helper()
	body := `{"email":"` + email + `","password":"` + password + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "schlass_session" {
			return c
		}
	}
	t.Fatal("login: no schlass_session cookie set")
	return nil
}
