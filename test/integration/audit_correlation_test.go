package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

// Every state-changing API request must result in an audit row whose
// metadata.correlation_id is populated with the UUIDv4 that RequestLogging
// injected into the request context. This ties the audit trail to the
// structured access log by a single UUID lookup — forensic investigators
// no longer need timestamp-joining.
func TestAuditCorrelationID_PopulatedOnSetupComplete(t *testing.T) {
	env := NewTestEnv(t)

	// Trigger setup via the full router (which wraps RequestLogging so the
	// correlation ID is stamped into the context before the handler fires).
	body, _ := json.Marshal(map[string]string{
		"email":            "admin@example.com",
		"password":         "CorrectHorse1Battery",
		"confirm_password": "CorrectHorse1Battery",
		"instance_name":    "Test Corp",
	})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/setup: want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var metadataJSON []byte
	err := env.Pool.QueryRow(context.Background(),
		`SELECT metadata FROM audit_logs WHERE event_type = 'setup.completed' ORDER BY created_at DESC LIMIT 1`).
		Scan(&metadataJSON)
	if err != nil {
		t.Fatalf("failed to read audit row: %v", err)
	}

	var metadata map[string]any
	if err := json.Unmarshal(metadataJSON, &metadata); err != nil {
		t.Fatalf("metadata is not valid JSON: %v (raw=%s)", err, string(metadataJSON))
	}

	cid, ok := metadata["correlation_id"].(string)
	if !ok || cid == "" {
		t.Fatalf("metadata.correlation_id missing or empty; metadata=%v", metadata)
	}
	uuidPattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if !uuidPattern.MatchString(cid) {
		t.Fatalf("correlation_id is not UUID-shaped: %q", cid)
	}
}

// Error-path coverage: login failure audit must also carry a correlation ID.
func TestAuditCorrelationID_PopulatedOnLoginFailure(t *testing.T) {
	env := NewTestEnv(t)

	// Complete setup first so the admin user exists.
	setupBody, _ := json.Marshal(map[string]string{
		"email":            "admin@example.com",
		"password":         "CorrectHorse1Battery",
		"confirm_password": "CorrectHorse1Battery",
		"instance_name":    "Test Corp",
	})
	setupReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/setup", bytes.NewReader(setupBody))
	setupReq.Header.Set("Content-Type", "application/json")
	setupRec := httptest.NewRecorder()
	env.Router.ServeHTTP(setupRec, setupReq)
	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup failed: %d %s", setupRec.Code, setupRec.Body.String())
	}

	// Attempt login with the wrong password to trigger a login.failed audit row.
	body, _ := json.Marshal(map[string]string{"email": "admin@example.com", "password": "WrongPass"})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000") // login handler enforces origin check
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}

	var metadataJSON []byte
	err := env.Pool.QueryRow(context.Background(),
		`SELECT metadata FROM audit_logs WHERE event_type = 'login.failed' ORDER BY created_at DESC LIMIT 1`).
		Scan(&metadataJSON)
	if err != nil {
		t.Fatalf("failed to read audit row: %v", err)
	}
	var metadata map[string]any
	_ = json.Unmarshal(metadataJSON, &metadata)
	if cid, _ := metadata["correlation_id"].(string); cid == "" {
		t.Fatalf("metadata.correlation_id missing on login.failed audit; metadata=%v", metadata)
	}
}
