//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuditProtectedEndpointsRequireRecentMFA(t *testing.T) {
	env := NewTestEnv(t)
	adminID := env.SeedAdmin(t, "admin@example.com", "CorrectHorse1Battery")
	victimID := env.DirectCreateUser(t, "victim@example.com", "user")

	routes := []struct {
		method string
		path   string
		body   string
		okCode int
	}{
		{"POST", "/api/audit/export", `{"since":"24h","view":"all","format":"csv"}`, http.StatusOK},
		{"PUT", "/api/audit/retention", `{"security_hot_days":365,"security_cold_years":1,"operational_days":90}`, http.StatusOK},
		{"POST", "/api/audit/purge", `{}`, http.StatusAccepted},
		{"PUT", "/api/audit/anchor", `{"backend":"none","bucket":"","path":"","events_per_anchor":10000,"interval_secs":3600}`, http.StatusOK},
		{"POST", "/api/audit/erase", `{"user_id":"` + victimID.String() + `","reason":"DSAR-2026-0042"}`, http.StatusOK},
	}

	for _, route := range routes {
		// Fresh session per route — MarkMFAVerified persists for 5 min, so a
		// shared session would leak the verified-stamp into the next route's
		// "without MFA" assertion.
		cookie := env.DirectCreateSession(t, adminID)

		req := httptest.NewRequestWithContext(t.Context(), route.method, route.path, bytes.NewBufferString(route.body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		env.Router.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s without MFA: want 401, got %d: %s", route.method, route.path, rec.Code, rec.Body.String())
		}
		var errBody map[string]any
		_ = json.NewDecoder(rec.Body).Decode(&errBody)
		if errBody["error"] != "STEPUP_REQUIRED" {
			t.Fatalf("%s %s without MFA: want STEPUP_REQUIRED, got %v", route.method, route.path, errBody)
		}

		if err := env.SessionStore.MarkMFAVerified(t.Context(), cookie.Value); err != nil {
			t.Fatalf("MarkMFAVerified: %v", err)
		}
		req = httptest.NewRequestWithContext(t.Context(), route.method, route.path, bytes.NewBufferString(route.body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		rec = httptest.NewRecorder()
		env.Router.ServeHTTP(rec, req)
		if rec.Code != route.okCode {
			t.Fatalf("%s %s with MFA: want %d, got %d: %s", route.method, route.path, route.okCode, rec.Code, rec.Body.String())
		}
	}
}
