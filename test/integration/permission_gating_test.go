package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Asserts that a non-super_admin receives 403 FORBIDDEN on every
// /api/users/* admin route. A permission-string typo in router.go or a
// gap in the RequirePermission middleware would surface here.
func TestPermissionGating_NonAdminBlockedFromAllUserRoutes(t *testing.T) {
	env := NewTestEnv(t)

	// Seed a super_admin so we can use the admin-only endpoints.
	adminEmail := "admin@example.com"
	adminPass := "CorrectHorse1Battery"
	env.SeedAdmin(t, adminEmail, adminPass)

	adminCookie := env.LoginAsAdmin(t, adminEmail, adminPass)

	// Create a non-admin user via POST /api/users (returns temp password).
	userEmail := "alice@example.com"
	createBody := bytes.NewBufferString(`{"email":"` + userEmail + `","role":"user"}`)
	createReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/users", createBody)
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Origin", "http://localhost:3000")
	createReq.AddCookie(adminCookie)
	createRec := httptest.NewRecorder()
	env.Router.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create user: want 201, got %d: %s", createRec.Code, createRec.Body.String())
	}
	var createResp struct {
		TemporaryPassword string `json:"temporary_password"`
	}
	if err := json.NewDecoder(createRec.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode create-user response: %v", err)
	}
	tempPass := createResp.TemporaryPassword

	// Non-admin logs in with temp password.
	userCookie := env.LoginAsAdmin(t, userEmail, tempPass)

	// Complete forced password change so the session is usable for other routes.
	newPass := "NewPass1Battery"
	chBody, _ := json.Marshal(map[string]string{
		"current_password": tempPass,
		"new_password":     newPass,
	})
	chReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/change-password", bytes.NewReader(chBody))
	chReq.Header.Set("Content-Type", "application/json")
	chReq.Header.Set("Origin", "http://localhost:3000")
	chReq.AddCookie(userCookie)
	chRec := httptest.NewRecorder()
	env.Router.ServeHTTP(chRec, chReq)
	if chRec.Code != http.StatusNoContent {
		t.Fatalf("change-password: want 204, got %d: %s", chRec.Code, chRec.Body.String())
	}

	// Log in again with the new password to get a fresh session.
	userCookie = env.LoginAsAdmin(t, userEmail, newPass)

	routes := []struct {
		method string
		path   string
		body   string
	}{
		{"GET", "/api/users", ""},
		{"POST", "/api/users", `{"email":"x@example.com","role":"user"}`},
		{"GET", "/api/users/00000000-0000-0000-0000-000000000000", ""},
		{"PATCH", "/api/users/00000000-0000-0000-0000-000000000000", `{"email":"y@example.com"}`},
		{"POST", "/api/users/00000000-0000-0000-0000-000000000000/disable", ""},
		{"POST", "/api/users/00000000-0000-0000-0000-000000000000/enable", ""},
		{"POST", "/api/users/00000000-0000-0000-0000-000000000000/reset-password", ""},
		{"DELETE", "/api/users/00000000-0000-0000-0000-000000000000", ""},
		{"GET", "/api/users/00000000-0000-0000-0000-000000000000/sessions", ""},
		{"DELETE", "/api/users/00000000-0000-0000-0000-000000000000/sessions", ""},
		{"DELETE", "/api/users/00000000-0000-0000-0000-000000000000/sessions/sometoken", ""},
	}

	for _, route := range routes {
		var bodyReader *bytes.Reader
		if route.body != "" {
			bodyReader = bytes.NewReader([]byte(route.body))
		} else {
			bodyReader = bytes.NewReader(nil)
		}
		req := httptest.NewRequestWithContext(t.Context(), route.method, route.path, bodyReader)
		req.Header.Set("Origin", "http://localhost:3000")
		req.AddCookie(userCookie)
		if route.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		env.Router.ServeHTTP(rec, req)

		var resBody map[string]any
		_ = json.NewDecoder(rec.Body).Decode(&resBody)

		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s: want 403, got %d (body=%v)", route.method, route.path, rec.Code, resBody)
			continue
		}
		if code, _ := resBody["error"].(string); code != "FORBIDDEN" {
			t.Errorf("%s %s: want error=FORBIDDEN, got %v", route.method, route.path, resBody["error"])
		}
	}
}
