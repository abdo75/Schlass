package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abdo75/Schlass/internal/crypto"
)

// TestUsers_RoleGate_RejectsNonAdmin proves that a session belonging to a
// non-super_admin user is rejected with 403 FORBIDDEN by the RequireRole
// middleware wired into every /api/users/* route in Task 5.
func TestUsers_RoleGate_RejectsNonAdmin(t *testing.T) {
	ctx := context.Background()
	env := NewTestEnv(t)

	// Seed a super_admin so the login handler can bootstrap, then also seed a
	// plain 'user' whose credentials we'll actually use for the 403 check.
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42Battery")

	hash, err := crypto.HashPassword("UserPass42Battery")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := env.Pool.Exec(ctx,
		`INSERT INTO users (email, password_hash, role, force_password_change)
		 VALUES ('viewer@example.com', $1, 'user', false)`,
		hash); err != nil {
		t.Fatalf("seed non-admin: %v", err)
	}

	cookie := env.LoginAsAdmin(t, "viewer@example.com", "UserPass42Battery")

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/users", nil)
	req.AddCookie(cookie)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "FORBIDDEN") {
		t.Fatalf("want FORBIDDEN, got %s", rec.Body.String())
	}
}

// TestUsers_RoleGate_AllowsSuperAdmin proves a super_admin session is not
// rejected at the role-gate layer. The stub handler currently responds 501,
// so the assertion is "not 403" rather than a specific status code.
func TestUsers_RoleGate_AllowsSuperAdmin(t *testing.T) {
	env := NewTestEnv(t)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42Battery")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42Battery")

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/users", nil)
	req.AddCookie(cookie)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("super_admin unexpectedly rejected by role gate")
	}
}
