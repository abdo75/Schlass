package integration

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestUsers_Create_HappyPath(t *testing.T) {
	env := NewTestEnv(t)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42Battery")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42Battery")

	body := bytes.NewBufferString(`{"email":"new@example.com","password":"NewTempPass42!","role":"user"}`)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/users", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify the row exists and force_password_change is true.
	var fpc bool
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT force_password_change FROM users WHERE email = $1`, "new@example.com",
	).Scan(&fpc); err != nil {
		t.Fatalf("query new user: %v", err)
	}
	if !fpc {
		t.Fatal("admin-created user should have force_password_change=true")
	}

	// Verify an audit row exists.
	var auditCount int
	_ = env.Pool.QueryRow(t.Context(),
		`SELECT count(*) FROM audit_logs WHERE event_type = 'user.created' AND actor_email = $1`,
		"admin@example.com").Scan(&auditCount)
	if auditCount != 1 {
		t.Fatalf("want 1 user.created audit row, got %d", auditCount)
	}
}

func TestUsers_Create_DuplicateEmail_409(t *testing.T) {
	env := NewTestEnv(t)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42Battery")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42Battery")

	body := bytes.NewBufferString(`{"email":"admin@example.com","password":"Whatever42Battery","role":"user"}`)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/users", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "EMAIL_ALREADY_EXISTS") {
		t.Fatalf("want EMAIL_ALREADY_EXISTS, got %s", rec.Body.String())
	}
}

func TestUsers_Create_WeakPassword_400(t *testing.T) {
	env := NewTestEnv(t)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42Battery")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42Battery")

	body := bytes.NewBufferString(`{"email":"weak@example.com","password":"short","role":"user"}`)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/users", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "PASSWORD_POLICY_VIOLATION") {
		t.Fatalf("want PASSWORD_POLICY_VIOLATION, got %s", rec.Body.String())
	}
}

func TestUsers_List_PaginationAndSearch(t *testing.T) {
	env := NewTestEnv(t)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42Battery")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42Battery")

	// Create 3 more users via the API.
	for _, email := range []string{"alice@example.com", "bob@example.com", "carol@example.com"} {
		body := bytes.NewBufferString(`{"email":"` + email + `","password":"UserPass42Battery","role":"user"}`)
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/users", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://localhost:3000")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		env.Router.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("seed %s: %d %s", email, rec.Code, rec.Body.String())
		}
	}

	// List all (expect 4: admin + 3 seeded)
	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/users", nil)
	req.AddCookie(cookie)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var listResp struct {
		Users []struct{ Email string } `json:"users"`
		Total int                      `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if listResp.Total != 4 {
		t.Fatalf("total: got %d want 4", listResp.Total)
	}

	// Search for "alice"
	req = httptest.NewRequestWithContext(t.Context(), "GET", "/api/users?email=alice", nil)
	req.AddCookie(cookie)
	req.Header.Set("Origin", "http://localhost:3000")
	rec = httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	_ = json.Unmarshal(rec.Body.Bytes(), &listResp)
	if listResp.Total != 1 {
		t.Fatalf("search total: got %d want 1", listResp.Total)
	}
	if listResp.Users[0].Email != "alice@example.com" {
		t.Fatalf("search result: %s", listResp.Users[0].Email)
	}
}
