//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abdo75/Schlass/internal/oidc"
	"github.com/abdo75/Schlass/internal/store"
)

// adminPost fires POST <path> against the test router with the given admin
// session cookie. Body may be nil for empty-body POSTs.
func adminPost(t *testing.T, env *TestEnv, cookie *http.Cookie, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var buf *bytes.Reader
	if body != nil {
		buf = bytes.NewReader(body)
	} else {
		buf = bytes.NewReader(nil)
	}
	req := httptest.NewRequestWithContext(t.Context(), "POST", path, buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	return rec
}

// adminGetJSON fires GET <path> and decodes the body as a generic map.
func adminGetJSON(t *testing.T, env *TestEnv, cookie *http.Cookie, path string) map[string]any {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), "GET", path, nil)
	req.Header.Set("Origin", "http://localhost:3000")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status=%d body=%s", path, rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("GET %s: decode: %v", path, err)
	}
	return out
}

// TestEmergencyRetire_RetiringKey_200 covers the happy path: a retiring key
// transitions to retired, disappears from JWKS, emits an audit row with
// reason=emergency, and a second attempt returns 409 ALREADY_RETIRED.
func TestEmergencyRetire_RetiringKey_200(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	ctx := context.Background()

	// Bootstrap the initial active key so rotate has something to retire.
	if err := oidc.BootstrapSigningKey(ctx, env.Pool, store.NewAuditStore(), env.Cfg.EncryptionKey); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	env.SeedAdmin(t, "admin@example.com", "CorrectHorse1Battery")
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	// Rotate once so the bootstrap key becomes retiring and a fresh one is active.
	rotRec := adminPost(t, env, adminCookie, "/api/admin/signing-keys/rotate", nil)
	if rotRec.Code != http.StatusNoContent {
		t.Fatalf("rotate: got %d, want 204: %s", rotRec.Code, rotRec.Body.String())
	}

	// Discover the retiring kid from the list endpoint.
	listResp := adminGetJSON(t, env, adminCookie, "/api/admin/signing-keys")
	retiringKID := ""
	for _, k := range listResp["keys"].([]any) {
		kk := k.(map[string]any)
		if kk["status"] == "retiring" {
			retiringKID = kk["kid"].(string)
			break
		}
	}
	if retiringKID == "" {
		t.Fatalf("no retiring key after rotate")
	}

	// Retire it now.
	rec := adminPost(t, env, adminCookie, "/api/admin/signing-keys/"+retiringKID+"/retire-now", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("retire-now: got %d, want 204: %s", rec.Code, rec.Body.String())
	}

	// Kid is gone from public JWKS.
	jwks := adminGetJSON(t, env, nil, "/.well-known/jwks.json")
	for _, k := range jwks["keys"].([]any) {
		if k.(map[string]any)["kid"] == retiringKID {
			t.Fatalf("retired kid still present in JWKS")
		}
	}

	// Audit row: oidc.signing_key.retired with metadata.reason=emergency for this kid.
	var metadataRaw []byte
	err := env.Pool.QueryRow(ctx, `
		SELECT metadata FROM audit_logs
		WHERE event_type = 'oidc.signing_key.retired'
		  AND target_id = $1
		ORDER BY created_at DESC
		LIMIT 1
	`, retiringKID).Scan(&metadataRaw)
	if err != nil {
		t.Fatalf("audit row lookup: %v", err)
	}
	var meta map[string]any
	if err := json.Unmarshal(metadataRaw, &meta); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if meta["reason"] != "emergency" {
		t.Fatalf("audit metadata.reason = %v, want \"emergency\"", meta["reason"])
	}

	// Second call = 409 ALREADY_RETIRED.
	rec2 := adminPost(t, env, adminCookie, "/api/admin/signing-keys/"+retiringKID+"/retire-now", nil)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("second retire-now: got %d, want 409: %s", rec2.Code, rec2.Body.String())
	}
	var errBody map[string]any
	_ = json.Unmarshal(rec2.Body.Bytes(), &errBody)
	if errBody["error"] != "ALREADY_RETIRED" {
		t.Fatalf("second retire-now error = %v, want ALREADY_RETIRED", errBody["error"])
	}
}

// TestEmergencyRetire_ActiveKey_409 — retiring the active key is rejected.
func TestEmergencyRetire_ActiveKey_409(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	ctx := context.Background()

	if err := oidc.BootstrapSigningKey(ctx, env.Pool, store.NewAuditStore(), env.Cfg.EncryptionKey); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	env.SeedAdmin(t, "admin@example.com", "CorrectHorse1Battery")
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	listResp := adminGetJSON(t, env, adminCookie, "/api/admin/signing-keys")
	activeKID := ""
	for _, k := range listResp["keys"].([]any) {
		kk := k.(map[string]any)
		if kk["status"] == "active" {
			activeKID = kk["kid"].(string)
			break
		}
	}
	if activeKID == "" {
		t.Fatalf("no active key at startup")
	}

	rec := adminPost(t, env, adminCookie, "/api/admin/signing-keys/"+activeKID+"/retire-now", nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("retire active: got %d, want 409: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "CANNOT_RETIRE_ACTIVE_KEY" {
		t.Fatalf("error code = %q, want CANNOT_RETIRE_ACTIVE_KEY", body["error"])
	}
}

// TestEmergencyRetire_UnknownKID_404 — retiring a non-existent kid is 404.
func TestEmergencyRetire_UnknownKID_404(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	env.SeedAdmin(t, "admin@example.com", "CorrectHorse1Battery")
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	rec := adminPost(t, env, adminCookie, "/api/admin/signing-keys/00000000-0000-0000-0000-000000000000/retire-now", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404: %s", rec.Code, rec.Body.String())
	}
}
