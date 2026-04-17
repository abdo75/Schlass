package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
