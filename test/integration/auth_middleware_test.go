package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthMiddleware_NoCookie_Returns401(t *testing.T) {
	env := setupIntegrationEnv(t)
	defer env.Cleanup()

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/me", nil)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)

	if rec.Code != 401 {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "INVALID_SESSION") {
		t.Fatalf("want INVALID_SESSION, got %s", rec.Body.String())
	}
}

func TestAuthMiddleware_ValidCookie_AllowsRequest(t *testing.T) {
	env := setupIntegrationEnv(t)
	defer env.Cleanup()
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")

	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/me", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthMiddleware_DisabledUser_Revokes(t *testing.T) {
	env := setupIntegrationEnv(t)
	defer env.Cleanup()
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")

	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	_, err := env.Pool.Exec(context.Background(),
		`UPDATE users SET status='disabled' WHERE email=$1`,
		"admin@example.com")
	if err != nil {
		t.Fatalf("disable user: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/me", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)

	if rec.Code != 401 {
		t.Fatalf("want 401 on disabled user, got %d", rec.Code)
	}

	var revokedCount int
	if err := env.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_logs WHERE event_type='session.revoked' AND actor_email=$1`,
		"admin@example.com").Scan(&revokedCount); err != nil {
		t.Fatalf("scan revoked count: %v", err)
	}
	if revokedCount == 0 {
		t.Fatal("expected session.revoked audit row")
	}
}

// Spec §5.2 test 12 — Valkey transient error returns 503, not 401.
func TestAuthMiddleware_ValkeyError_Returns503(t *testing.T) {
	env := setupIntegrationEnv(t)
	defer env.Cleanup()
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")

	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	env.StopValkey(t)
	defer env.StartValkey(t)

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/me", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 during Valkey outage, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "SERVICE_UNAVAILABLE") {
		t.Fatalf("want SERVICE_UNAVAILABLE, got %s", rec.Body.String())
	}
}
