//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/instanceconfig"
	"github.com/abdo75/Schlass/internal/middleware"
	"github.com/abdo75/Schlass/internal/server"
	"github.com/abdo75/Schlass/internal/users"
)

func setupRouter(env *TestEnv) http.Handler {
	configStore := instanceconfig.NewStore()
	userStore := users.NewStore()
	auditStore := audit.NewStore()
	encKey := []byte("test-encryption-key-32-bytes!!!!")
	instanceConfig := instanceconfig.NewService(configStore, encKey)

	setupHandler := server.NewSetupHandler(env.Pool, instanceConfig, configStore, userStore, auditStore, nil)
	healthHandler := server.NewHealthHandler(env.Pool, env.ValkeyClient)
	setupRL := middleware.NewRateLimiter(env.ValkeyClient, "ratelimit:test:setup", 5, time.Minute)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", healthHandler.GetHealth)
	mux.Handle("GET /api/setup", setupRL.Middleware(http.HandlerFunc(setupHandler.GetSetup)))
	mux.Handle("POST /api/setup", setupRL.Middleware(http.HandlerFunc(setupHandler.PostSetup)))

	return middleware.SecurityHeaders(middleware.RequestLogging(mux))
}

func TestSetup_CreatesAdminAndMarksComplete(t *testing.T) {
	env := NewTestEnv(t)
	router := setupRouter(env)

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/setup", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/setup: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var getResp map[string]bool
	if err := json.NewDecoder(rec.Body).Decode(&getResp); err != nil {
		t.Fatalf("failed to decode GET /api/setup response: %v", err)
	}
	if !getResp["setup_required"] {
		t.Fatal("expected setup_required=true")
	}

	body := map[string]string{
		"email":            "admin@test.com",
		"password":         "SecurePass123!",
		"confirm_password": "SecurePass123!",
		"instance_name":    "Test Corp",
	}
	bodyJSON, _ := json.Marshal(body)
	req = httptest.NewRequestWithContext(t.Context(), "POST", "/api/setup", bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/setup: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var postResp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&postResp); err != nil {
		t.Fatalf("failed to decode POST /api/setup response: %v", err)
	}
	if postResp["redirect"] != "/login" {
		t.Fatalf("expected redirect=/login, got %s", postResp["redirect"])
	}

	var email string
	var role string
	err := env.Pool.QueryRow(t.Context(),
		"SELECT email, role FROM users WHERE email = $1", "admin@test.com",
	).Scan(&email, &role)
	if err != nil {
		t.Fatalf("failed to query admin user: %v", err)
	}
	if role != "super_admin" {
		t.Fatalf("expected role=super_admin, got %s", role)
	}

	var eventType string
	var outcome string
	err = env.Pool.QueryRow(t.Context(),
		"SELECT event_type, outcome FROM audit_logs WHERE actor_email = $1", "admin@test.com",
	).Scan(&eventType, &outcome)
	if err != nil {
		t.Fatalf("failed to query audit log: %v", err)
	}
	if eventType != "setup.completed" || outcome != "success" {
		t.Fatalf("unexpected audit log: event=%s outcome=%s", eventType, outcome)
	}
}

func TestSetupReturns404AfterCompletion(t *testing.T) {
	env := NewTestEnv(t)
	router := setupRouter(env)

	body := map[string]string{
		"email":            "admin@test.com",
		"password":         "SecurePass123!",
		"confirm_password": "SecurePass123!",
		"instance_name":    "Test Corp",
	}
	bodyJSON, _ := json.Marshal(body)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/setup", bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("setup failed: %d %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequestWithContext(t.Context(), "GET", "/api/setup", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after setup, got %d", rec.Code)
	}

	bodyJSON, _ = json.Marshal(body)
	req = httptest.NewRequestWithContext(t.Context(), "POST", "/api/setup", bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for POST after setup, got %d", rec.Code)
	}
}

func TestSetupRejectsWeakPassword(t *testing.T) {
	env := NewTestEnv(t)
	router := setupRouter(env)

	body := map[string]string{
		"email":            "admin@test.com",
		"password":         "weak",
		"confirm_password": "weak",
		"instance_name":    "Test Corp",
	}
	bodyJSON, _ := json.Marshal(body)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/setup", bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for weak password, got %d: %s", rec.Code, rec.Body.String())
	}

	var errResp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp["error"] != "PASSWORD_POLICY_VIOLATION" {
		t.Fatalf("expected PASSWORD_POLICY_VIOLATION, got %s", errResp["error"])
	}
}

func TestSetupRejectsInvalidEmail(t *testing.T) {
	env := NewTestEnv(t)
	router := setupRouter(env)

	body := map[string]string{
		"email":            "not-an-email",
		"password":         "SecurePass123!",
		"confirm_password": "SecurePass123!",
		"instance_name":    "Test Corp",
	}
	bodyJSON, _ := json.Marshal(body)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/setup", bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid email, got %d", rec.Code)
	}
}

func TestSetupRejectsMismatchedPasswords(t *testing.T) {
	env := NewTestEnv(t)
	router := setupRouter(env)

	body := map[string]string{
		"email":            "admin@test.com",
		"password":         "SecurePass123!",
		"confirm_password": "DifferentPass123!",
		"instance_name":    "Test Corp",
	}
	bodyJSON, _ := json.Marshal(body)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/setup", bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for mismatched passwords, got %d", rec.Code)
	}
}

func TestSetupRejectsMissingFields(t *testing.T) {
	env := NewTestEnv(t)
	router := setupRouter(env)

	tests := []struct {
		name string
		body map[string]string
	}{
		{"missing email", map[string]string{"password": "SecurePass123!", "confirm_password": "SecurePass123!", "instance_name": "X"}},
		{"missing password", map[string]string{"email": "a@b.com", "confirm_password": "SecurePass123!", "instance_name": "X"}},
		{"missing instance_name", map[string]string{"email": "a@b.com", "password": "SecurePass123!", "confirm_password": "SecurePass123!"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyJSON, _ := json.Marshal(tt.body)
			req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/setup", bytes.NewReader(bodyJSON))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for %s, got %d: %s", tt.name, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestSetupRateLimiting(t *testing.T) {
	env := NewTestEnv(t)
	configStore := instanceconfig.NewStore()
	userStore := users.NewStore()
	auditStore := audit.NewStore()
	encKey := []byte("test-encryption-key-32-bytes!!!!")
	instanceConfig := instanceconfig.NewService(configStore, encKey)
	setupHandler := server.NewSetupHandler(env.Pool, instanceConfig, configStore, userStore, auditStore, nil)

	rl := middleware.NewRateLimiter(env.ValkeyClient, "ratelimit:test:rl", 3, time.Minute)
	h := rl.Middleware(http.HandlerFunc(setupHandler.GetSetup))

	for i := 0; i < 3; i++ {
		req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/setup", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/setup", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 4th request, got %d", rec.Code)
	}

	retryAfter := rec.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Fatal("expected Retry-After header")
	}
}

func TestSetup_PersisstsInstanceNameToConfig(t *testing.T) {
	env := NewTestEnv(t)
	router := setupRouter(env)

	// Complete setup with a distinctive instance_name that should be persisted
	// to instance_config. This verifies the TOTP issuer fix (commit 61331fd)
	// will read the correct name from config on fresh installs.
	const wantName = "ACME Corporation"
	body := map[string]string{
		"email":            "admin@test.com",
		"password":         "SecurePass123!",
		"confirm_password": "SecurePass123!",
		"instance_name":    wantName,
	}
	bodyJSON, _ := json.Marshal(body)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/setup", bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/setup: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Assert instance_config.instance_name was persisted with the correct value.
	// instance_config.value is JSONB; strings are stored as quoted JSON strings.
	var got string
	err := env.Pool.QueryRow(t.Context(),
		"SELECT value FROM instance_config WHERE key = 'instance_name'",
	).Scan(&got)
	if err != nil {
		t.Fatalf("query instance_config.instance_name: %v", err)
	}

	// Stored as JSON, so "ACME Corporation" is wrapped in quotes
	wantJSON := `"` + wantName + `"`
	if got != wantJSON {
		t.Fatalf("instance_config.instance_name: want %q, got %q", wantJSON, got)
	}
}
