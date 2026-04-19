//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// clientCreateResp is the decoded body of a successful POST /api/clients.
type clientCreateResp struct {
	ClientID     string          `json:"client_id"`
	ClientSecret string          `json:"client_secret"`
	Client       json.RawMessage `json:"client"`
}

// adminCreateClient POSTs /api/clients with the given payload and returns the
// parsed response. Fails the test immediately on a non-201 status.
func adminCreateClient(t *testing.T, env *TestEnv, cookie *http.Cookie, payload map[string]any) *clientCreateResp {
	t.Helper()
	body, _ := json.Marshal(payload)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/clients", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create client: status %d, body %s", w.Code, w.Body.String())
	}
	var resp clientCreateResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	return &resp
}

func TestClientsCRUD_HappyPath(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()
	env.SeedAdmin(t, "admin-crud@x.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin-crud@x.com", "CorrectHorse42!")

	created := adminCreateClient(t, env, cookie, map[string]any{
		"name":                "customer-portal",
		"client_type":         "confidential",
		"redirect_uris":       []string{"https://portal.example.com/cb"},
		"allowed_grant_types": []string{"authorization_code", "refresh_token"},
		"allowed_scopes":      []string{"openid", "profile", "email", "offline_access"},
	})
	if created.ClientSecret == "" {
		t.Fatal("client_secret empty in create response")
	}
	if created.ClientID == "" {
		t.Fatal("client_id empty in create response")
	}

	// Audit row present
	var count int
	if err := env.Pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_logs
		WHERE event_type = 'client.created' AND target_id = $1
	`, created.ClientID).Scan(&count); err != nil {
		t.Fatalf("query client.created audit: %v", err)
	}
	if count != 1 {
		t.Errorf("client.created audit count = %d, want 1", count)
	}

	// Detail — GET /api/clients/:id
	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/clients/"+created.ClientID, nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("detail: %d, body %s", w.Code, w.Body.String())
	}

	// List default (active)
	req = httptest.NewRequestWithContext(t.Context(), "GET", "/api/clients", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d, body %s", w.Code, w.Body.String())
	}

	// Disable
	req = httptest.NewRequestWithContext(t.Context(), "POST", "/api/clients/"+created.ClientID+"/disable", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("disable: %d, body %s", w.Code, w.Body.String())
	}

	// Verify audit row for disable
	if err := env.Pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_logs
		WHERE event_type = 'client.disabled' AND target_id = $1
	`, created.ClientID).Scan(&count); err != nil {
		t.Fatalf("query client.disabled audit: %v", err)
	}
	if count != 1 {
		t.Errorf("client.disabled audit count = %d, want 1", count)
	}

	// Enable
	req = httptest.NewRequestWithContext(t.Context(), "POST", "/api/clients/"+created.ClientID+"/enable", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("enable: %d, body %s", w.Code, w.Body.String())
	}

	// Verify audit row for enable
	if err := env.Pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_logs
		WHERE event_type = 'client.enabled' AND target_id = $1
	`, created.ClientID).Scan(&count); err != nil {
		t.Fatalf("query client.enabled audit: %v", err)
	}
	if count != 1 {
		t.Errorf("client.enabled audit count = %d, want 1", count)
	}
}

func TestClientsPATCH_PerFieldAuditCanonicalOrder(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()
	env.SeedAdmin(t, "admin-patch@x.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin-patch@x.com", "CorrectHorse42!")

	created := adminCreateClient(t, env, cookie, map[string]any{
		"name":                "old-name",
		"client_type":         "confidential",
		"redirect_uris":       []string{"https://x/cb"},
		"allowed_grant_types": []string{"authorization_code"},
		"allowed_scopes":      []string{"openid"},
	})

	body, _ := json.Marshal(map[string]any{
		"name":           "new-name",
		"allowed_scopes": []string{"openid", "profile"},
	})
	req := httptest.NewRequestWithContext(t.Context(), "PATCH", "/api/clients/"+created.ClientID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("patch: %d, body %s", w.Code, w.Body.String())
	}

	rows, err := env.Pool.Query(ctx, `
		SELECT event_type FROM audit_logs
		WHERE target_id = $1 AND event_type LIKE 'client.%_updated'
		ORDER BY created_at ASC
	`, created.ClientID)
	if err != nil {
		t.Fatalf("query audits: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var et string
		if err := rows.Scan(&et); err != nil {
			t.Fatalf("scan event_type: %v", err)
		}
		got = append(got, et)
	}
	if rows.Err() != nil {
		t.Fatalf("rows error: %v", rows.Err())
	}

	want := []string{"client.name_updated", "client.scopes_updated"}
	if len(got) != len(want) {
		t.Fatalf("audit rows: got %v, want %v", got, want)
	}
	for i, ev := range want {
		if got[i] != ev {
			t.Errorf("audit[%d] = %q, want %q", i, got[i], ev)
		}
	}
}

func TestClientsPATCH_NoOp_ZeroAuditRows(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()
	env.SeedAdmin(t, "admin-noop@x.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin-noop@x.com", "CorrectHorse42!")

	created := adminCreateClient(t, env, cookie, map[string]any{
		"name":                "same-name",
		"client_type":         "confidential",
		"redirect_uris":       []string{"https://x/cb"},
		"allowed_grant_types": []string{"authorization_code"},
		"allowed_scopes":      []string{"openid"},
	})

	// PATCH with the same name — no actual change.
	body, _ := json.Marshal(map[string]any{"name": "same-name"})
	req := httptest.NewRequestWithContext(t.Context(), "PATCH", "/api/clients/"+created.ClientID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("no-op patch: %d, body %s", w.Code, w.Body.String())
	}

	var count int
	if err := env.Pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_logs
		WHERE target_id = $1 AND event_type LIKE 'client.%_updated'
	`, created.ClientID).Scan(&count); err != nil {
		t.Fatalf("query no-op audit rows: %v", err)
	}
	if count != 0 {
		t.Errorf("no-op PATCH emitted %d audit rows, want 0", count)
	}
}

// TestClientsDELETE_NonAdmin_403 verifies a 'user' role cannot delete a client.
func TestClientsDELETE_NonAdmin_403(t *testing.T) {
	env := NewTestEnv(t)
	// DirectCreateUser inserts a 'user'-role account directly via the store.
	env.DirectCreateUser(t, "regular@x.com", "user")

	// DirectCreateSession skips the login handler (and MFA logic) entirely.
	userID := env.GetUserIDByEmail(t, "regular@x.com")
	cookie := env.DirectCreateSession(t, userID)

	req := httptest.NewRequestWithContext(t.Context(), "DELETE", "/api/clients/11111111-1111-1111-1111-111111111111", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("non-admin delete: got %d, want 403", w.Code)
	}
}
