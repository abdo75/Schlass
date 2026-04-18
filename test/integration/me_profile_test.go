package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPatchProfile_Happy(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	body, _ := json.Marshal(map[string]string{"email": "admin.new@example.com"})
	req := httptest.NewRequestWithContext(t.Context(), "PATCH", "/api/me/profile", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var out struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.User.Email != "admin.new@example.com" {
		t.Fatalf("want admin.new@example.com, got %q", out.User.Email)
	}

	// Audit row: user.updated with self_update=true + email from/to metadata.
	var evt, metaJSON string
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT event_type, metadata::text FROM audit_logs WHERE event_type = 'user.updated' ORDER BY created_at DESC LIMIT 1`,
	).Scan(&evt, &metaJSON); err != nil {
		t.Fatalf("audit row scan failed: %v", err)
	}
	if evt != "user.updated" {
		t.Fatal("user.updated audit row missing")
	}
	if !strings.Contains(metaJSON, "self_update") {
		t.Fatalf("audit metadata missing self_update: %s", metaJSON)
	}
}

func TestPatchProfile_CaseNormalization(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	body, _ := json.Marshal(map[string]string{"email": "Admin.UPPER@Example.COM"})
	req := httptest.NewRequestWithContext(t.Context(), "PATCH", "/api/me/profile", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var out struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.User.Email != "admin.upper@example.com" {
		t.Fatalf("want lowercased email, got %q", out.User.Email)
	}
}

func TestPatchProfile_InvalidEmail(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	body, _ := json.Marshal(map[string]string{"email": "not-an-email"})
	req := httptest.NewRequestWithContext(t.Context(), "PATCH", "/api/me/profile", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestPatchProfile_EmailConflict(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	// Create a second user.
	env.DirectCreateUser(t, "other@example.com", "user")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	// Admin tries to take the second user's email.
	body, _ := json.Marshal(map[string]string{"email": "other@example.com"})
	req := httptest.NewRequestWithContext(t.Context(), "PATCH", "/api/me/profile", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409, got %d: %s", rec.Code, rec.Body.String())
	}
	var respBody map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &respBody)
	if respBody["error"] != "EMAIL_ALREADY_EXISTS" {
		t.Fatalf("want EMAIL_ALREADY_EXISTS, got %v", respBody["error"])
	}
}

func TestPatchProfile_NoOp_NoAudit(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	var auditCountBefore int
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM audit_logs WHERE event_type = 'user.updated'`,
	).Scan(&auditCountBefore); err != nil {
		t.Fatalf("audit count before scan: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"email": "admin@example.com"}) // unchanged
	req := httptest.NewRequestWithContext(t.Context(), "PATCH", "/api/me/profile", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}

	var auditCountAfter int
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM audit_logs WHERE event_type = 'user.updated'`,
	).Scan(&auditCountAfter); err != nil {
		t.Fatalf("audit count after scan: %v", err)
	}
	if auditCountAfter != auditCountBefore {
		t.Fatalf("no-op should not audit; before=%d after=%d", auditCountBefore, auditCountAfter)
	}
}

func TestPatchProfile_Unauthenticated(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	body, _ := json.Marshal(map[string]string{"email": "anyone@example.com"})
	req := httptest.NewRequestWithContext(t.Context(), "PATCH", "/api/me/profile", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No cookie.
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}
