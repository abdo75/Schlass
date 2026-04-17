package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// POST /api/users must reject a case-variant duplicate of an existing email.
// After migration 000012 this is enforced by the functional unique index on
// LOWER(email), independent of the handler's lowercasing — so even a future
// path that bypasses handler canonicalization still fails loudly.
func TestCreateUser_CaseInsensitiveUniqueness(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	adminEmail := "admin@example.com"
	adminPass := "CorrectHorse1Battery"
	env.SeedAdmin(t, adminEmail, adminPass)
	adminCookie := env.LoginAsAdmin(t, adminEmail, adminPass)

	// Create alice@example.com via the admin API.
	body1, _ := json.Marshal(map[string]string{"email": "alice@example.com", "role": "user"})
	req1 := httptest.NewRequestWithContext(t.Context(), "POST", "/api/users", bytes.NewReader(body1))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Origin", "http://localhost:3000")
	req1.AddCookie(adminCookie)
	rec1 := httptest.NewRecorder()
	env.Router.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusCreated {
		t.Fatalf("first create: want 201, got %d: %s", rec1.Code, rec1.Body.String())
	}

	// Attempt to create ALICE@example.com — same identity, different case.
	body2, _ := json.Marshal(map[string]string{"email": "ALICE@example.com", "role": "user"})
	req2 := httptest.NewRequestWithContext(t.Context(), "POST", "/api/users", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Origin", "http://localhost:3000")
	req2.AddCookie(adminCookie)
	rec2 := httptest.NewRecorder()
	env.Router.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("case-variant duplicate: want 409, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var resBody map[string]any
	_ = json.Unmarshal(rec2.Body.Bytes(), &resBody)
	if code, _ := resBody["error"].(string); code != "EMAIL_ALREADY_EXISTS" {
		t.Errorf("want error=EMAIL_ALREADY_EXISTS, got %v", resBody["error"])
	}
}

// Login must succeed regardless of the case the admin types: admin@example.com,
// ADMIN@example.com, Admin@Example.COM should all resolve to the same user row.
// This protects against Luxembourg-market onboarding where mixed-case email
// entries on a shared device would otherwise trigger "invalid credentials".
func TestLogin_CaseInsensitiveEmail(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	adminEmail := "admin@example.com"
	adminPass := "CorrectHorse1Battery"
	env.SeedAdmin(t, adminEmail, adminPass)

	// Disable MFA so each login attempt takes the legacy 200-path.
	if _, err := env.Pool.Exec(t.Context(), `UPDATE instance_config SET value = 'false' WHERE key = 'mfa_required'`); err != nil {
		t.Fatalf("disable mfa: %v", err)
	}

	cases := []string{
		"admin@example.com",  // canonical
		"ADMIN@example.com",  // upper local part
		"Admin@Example.COM",  // fully mixed
		"admin@EXAMPLE.com",  // upper domain
	}
	for _, email := range cases {
		body, _ := json.Marshal(map[string]string{"email": email, "password": adminPass})
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		env.Router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("login with casing %q: want 200, got %d (body=%s)", email, rec.Code, rec.Body.String())
		}
	}
}
