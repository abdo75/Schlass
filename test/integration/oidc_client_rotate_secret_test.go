//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/abdo75/Schlass/internal/store"
)

func TestClientRotateSecret_OverlapWindow(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()
	env.SeedAdmin(t, "admin-rotate@x.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin-rotate@x.com", "CorrectHorse42!")

	created := adminCreateClient(t, env, cookie, map[string]any{
		"name":                "rotator",
		"client_type":         "confidential",
		"redirect_uris":       []string{"https://x/cb"},
		"allowed_grant_types": []string{"authorization_code", "refresh_token"},
		"allowed_scopes":      []string{"openid", "offline_access"},
	})
	originalSecret := created.ClientSecret

	// Rotate
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/clients/"+created.ClientID+"/rotate-secret", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("rotate: %d, body %s", w.Code, w.Body.String())
	}

	var resp struct {
		ClientID                string    `json:"client_id"`
		ClientSecret            string    `json:"client_secret"`
		PreviousSecretExpiresAt time.Time `json:"previous_secret_expires_at"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode rotate response: %v", err)
	}
	newSecret := resp.ClientSecret
	if newSecret == "" {
		t.Fatal("new client_secret empty in rotate response")
	}
	if newSecret == originalSecret {
		t.Error("new secret matches original — rotation did nothing")
	}
	if time.Until(resp.PreviousSecretExpiresAt) < 23*time.Hour {
		t.Errorf("previous_secret_expires_at = %v, want ~24h future", resp.PreviousSecretExpiresAt)
	}

	// Both secrets must verify within the overlap window.
	// VerifySecret calls GetByID (active-only), so the client must be active.
	s := store.NewClientStore()
	okOld, err := s.VerifySecret(ctx, env.Pool, created.ClientID, originalSecret)
	if err != nil {
		t.Fatalf("VerifySecret(old): %v", err)
	}
	if !okOld {
		t.Error("old secret must still verify within the overlap window")
	}

	okNew, err := s.VerifySecret(ctx, env.Pool, created.ClientID, newSecret)
	if err != nil {
		t.Fatalf("VerifySecret(new): %v", err)
	}
	if !okNew {
		t.Error("new secret must verify immediately after rotation")
	}

	// Audit row must not contain any plaintext secret.
	var meta json.RawMessage
	if err := env.Pool.QueryRow(ctx, `
		SELECT metadata FROM audit_logs
		WHERE target_id = $1 AND event_type = 'client.secret_rotated'
	`, created.ClientID).Scan(&meta); err != nil {
		t.Fatalf("query audit row: %v", err)
	}
	if bytes.Contains(meta, []byte(newSecret)) {
		t.Error("audit metadata contains plaintext new secret")
	}
	if bytes.Contains(meta, []byte(originalSecret)) {
		t.Error("audit metadata contains plaintext original secret")
	}

	// Fast-forward the previous-secret expiry to the past.
	if _, err := env.Pool.Exec(ctx, `
		UPDATE clients
		SET secret_previous_expires_at = now() - interval '1 second'
		WHERE id = $1
	`, created.ClientID); err != nil {
		t.Fatalf("fast-forward expiry: %v", err)
	}

	// Old secret must NOT verify after the overlap window closes.
	okOldAfter, err := s.VerifySecret(ctx, env.Pool, created.ClientID, originalSecret)
	if err != nil {
		t.Fatalf("VerifySecret(old, after window): %v", err)
	}
	if okOldAfter {
		t.Error("old secret must NOT verify after overlap window closes")
	}

	// New secret must still verify.
	okNewAfter, err := s.VerifySecret(ctx, env.Pool, created.ClientID, newSecret)
	if err != nil {
		t.Fatalf("VerifySecret(new, after window): %v", err)
	}
	if !okNewAfter {
		t.Error("new secret must still verify after overlap window closes")
	}
}
