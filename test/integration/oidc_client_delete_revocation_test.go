//go:build integration

package integration

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestClientDelete_RevokesOutstandingAT is the end-to-end revocation path:
//  1. Admin creates a client via /api/clients
//  2. Mint a valid AT for that client using the AT-minting helpers from
//     bearer_auth_test.go (seedBearerSigningKey + mintAccessToken)
//  3. GET /userinfo with the AT — expect 200
//  4. Admin DELETE /api/clients/:id — expect 204
//  5. GET /userinfo with the SAME AT — expect 401 (client:revoke_before cutoff)
//  6. Audit row client.deleted is present even though the client row is gone
func TestClientDelete_RevokesOutstandingAT(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	// Seed admin and sign a token for the bearer auth middleware to accept.
	kid, priv := seedBearerSigningKey(t, env)
	userID := env.SeedAdmin(t, "admin-del-at@x.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin-del-at@x.com", "CorrectHorse42!")

	// Create the client via the real API so audit trail is written.
	created := adminCreateClient(t, env, cookie, map[string]any{
		"name":                "doomed-at-client",
		"client_type":         "confidential",
		"redirect_uris":       []string{"https://x/cb"},
		"allowed_grant_types": []string{"authorization_code"},
		"allowed_scopes":      []string{"openid"},
	})

	// Mint an AT whose audience is the new client's ID.
	// BearerAuth (with Valkey) checks both user and client revoke_before.
	token := mintAccessToken(t, env.Cfg.SchlassPublicURL, userID.String(), created.ClientID, kid, priv, nil)

	// Pre-delete: /userinfo must return 200.
	req := httptest.NewRequestWithContext(t.Context(), "GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("pre-delete /userinfo: status %d, body %s", w.Code, w.Body.String())
	}

	// DELETE /api/clients/:id — expect 204.
	delReq := httptest.NewRequestWithContext(t.Context(), "DELETE", "/api/clients/"+created.ClientID, bytes.NewReader(nil))
	delReq.AddCookie(cookie)
	dw := httptest.NewRecorder()
	env.Router.ServeHTTP(dw, delReq)
	if dw.Code != http.StatusNoContent {
		t.Fatalf("delete: %d, body %s", dw.Code, dw.Body.String())
	}

	// Post-delete: same AT must now be rejected — client:revoke_before is set.
	req = httptest.NewRequestWithContext(t.Context(), "GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("post-delete /userinfo: status %d, want 401", w.Code)
	}

	// Valkey cutoff key must be set.
	val, err := env.ValkeyClient.Get(ctx, "client:revoke_before:"+created.ClientID).Result()
	if err != nil {
		t.Fatalf("client:revoke_before not set in Valkey: %v", err)
	}
	if val == "" {
		t.Error("client:revoke_before value is empty")
	}

	// Audit row client.deleted must be preserved even though the client row is gone.
	var count int
	if err := env.Pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_logs
		WHERE target_id = $1 AND event_type = 'client.deleted'
	`, created.ClientID).Scan(&count); err != nil {
		t.Fatalf("query client.deleted audit: %v", err)
	}
	if count != 1 {
		t.Errorf("client.deleted audit count = %d, want 1", count)
	}
}

// TestClientDelete_SetsRevokeBeforeCutoff is a narrower companion that verifies
// the Valkey cutoff and audit preservation when no pre-minted token is needed.
// Useful for quickly isolating the Valkey write path from the full bearer flow.
func TestClientDelete_SetsRevokeBeforeCutoff(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()
	env.SeedAdmin(t, "admin-del-cutoff@x.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin-del-cutoff@x.com", "CorrectHorse42!")

	created := adminCreateClient(t, env, cookie, map[string]any{
		"name":                "doomed-cutoff",
		"client_type":         "confidential",
		"redirect_uris":       []string{"https://x/cb"},
		"allowed_grant_types": []string{"authorization_code"},
		"allowed_scopes":      []string{"openid"},
	})

	req := httptest.NewRequestWithContext(t.Context(), "DELETE", "/api/clients/"+created.ClientID, bytes.NewReader(nil))
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d, body %s", w.Code, w.Body.String())
	}

	// Valkey cutoff must be set post-commit.
	val, err := env.ValkeyClient.Get(ctx, "client:revoke_before:"+created.ClientID).Result()
	if err != nil {
		t.Fatalf("client:revoke_before not set: %v", err)
	}
	if val == "" {
		t.Error("client:revoke_before value empty")
	}

	// Audit row must survive the hard delete (audit_logs row is unaffected by
	// the clients FK cascade — audit_logs has no FK to clients).
	var count int
	if err := env.Pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_logs
		WHERE target_id = $1 AND event_type = 'client.deleted'
	`, created.ClientID).Scan(&count); err != nil {
		t.Fatalf("query audit row: %v", err)
	}
	if count != 1 {
		t.Errorf("client.deleted audit count = %d, want 1", count)
	}
}
