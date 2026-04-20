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
)

// adminPatch fires PATCH <path> against the test router with the given admin
// session cookie. Body may be nil for empty-body PATCHes (rare).
func adminPatch(t *testing.T, env *TestEnv, cookie *http.Cookie, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var buf *bytes.Reader
	if body != nil {
		buf = bytes.NewReader(body)
	} else {
		buf = bytes.NewReader(nil)
	}
	req := httptest.NewRequestWithContext(t.Context(), "PATCH", path, buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	return rec
}

// TestGetSettings_ReturnsSnapshot checks that the one-shot GET returns every
// domain, exposes the SMTP password only via the _set boolean, and never
// leaks the underlying ciphertext or plaintext.
func TestGetSettings_ReturnsSnapshot(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	env.SeedAdmin(t, "admin@example.com", "CorrectHorse1Battery")
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	resp := adminGetJSON(t, env, adminCookie, "/api/settings")

	gen, ok := resp["general"].(map[string]any)
	if !ok {
		t.Fatalf("snapshot.general missing or wrong shape: %#v", resp["general"])
	}
	if _, ok := gen["instance_name"]; !ok {
		t.Fatal("snapshot.general.instance_name missing")
	}
	sec, ok := resp["security"].(map[string]any)
	if !ok {
		t.Fatalf("snapshot.security missing: %#v", resp["security"])
	}
	if _, ok := sec["mfa_required"]; !ok {
		t.Fatal("snapshot.security.mfa_required missing")
	}
	if _, ok := sec["password_min_length"]; !ok {
		t.Fatal("snapshot.security.password_min_length missing")
	}
	if _, ok := sec["lockout_threshold"]; !ok {
		t.Fatal("snapshot.security.lockout_threshold missing")
	}
	tok, ok := resp["tokens"].(map[string]any)
	if !ok {
		t.Fatalf("snapshot.tokens missing: %#v", resp["tokens"])
	}
	if _, ok := tok["access_token_ttl_secs"]; !ok {
		t.Fatal("snapshot.tokens.access_token_ttl_secs missing")
	}
	email, ok := resp["email"].(map[string]any)
	if !ok {
		t.Fatalf("snapshot.email missing: %#v", resp["email"])
	}
	if _, ok := email["smtp_password_set"]; !ok {
		t.Fatal("snapshot.email.smtp_password_set missing")
	}
	if _, ok := email["smtp_password"]; ok {
		t.Fatal("snapshot.email.smtp_password leaked in response")
	}
}

// TestPatchGeneral_SetsInstanceName_AndAudits covers the happy path: the
// PATCH returns 200 with the updated snapshot subset, the instance_name
// row is mutated, and exactly one config.instance_name.changed audit row
// lands inside the same transaction. A follow-up no-op PATCH (same value)
// must NOT write a second audit row — the handler short-circuits to
// preserve a clean audit trail against UI double-clicks and retries.
func TestPatchGeneral_SetsInstanceName_AndAudits(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	env.SeedAdmin(t, "admin@example.com", "CorrectHorse1Battery")
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	body, _ := json.Marshal(map[string]any{"instance_name": "Acme Identity"})
	rec := adminPatch(t, env, adminCookie, "/api/settings/general", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := resp["instance_name"]; got != "Acme Identity" {
		t.Fatalf("response instance_name = %v, want %q", got, "Acme Identity")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var count int
	if err := env.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_logs
		WHERE event_type = 'config.instance_name.changed'
		  AND metadata->>'new_value' = 'Acme Identity'
	`).Scan(&count); err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if count != 1 {
		t.Fatalf("want 1 audit row, got %d", count)
	}

	// Row under instance_config was actually updated.
	var stored string
	if err := env.Pool.QueryRow(ctx,
		`SELECT value::text FROM instance_config WHERE key = 'instance_name'`,
	).Scan(&stored); err != nil {
		t.Fatalf("read instance_config: %v", err)
	}
	if stored != `"Acme Identity"` {
		t.Fatalf("instance_config row = %s, want %q", stored, `"Acme Identity"`)
	}

	// No-op repeat — must NOT write a second audit row.
	rec2 := adminPatch(t, env, adminCookie, "/api/settings/general", body)
	if rec2.Code != http.StatusOK {
		t.Fatalf("no-op repeat: got %d, want 200: %s", rec2.Code, rec2.Body.String())
	}
	if err := env.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM audit_logs WHERE event_type = 'config.instance_name.changed'`,
	).Scan(&count); err != nil {
		t.Fatalf("audit query 2: %v", err)
	}
	if count != 1 {
		t.Fatalf("no-op PATCH wrote extra audit row; got %d rows total", count)
	}
}

// TestPatchGeneral_ValidationError verifies the empty-string guard returns
// 400 with the validator's stable uppercase code — the frontend maps this
// to an i18n key.
func TestPatchGeneral_ValidationError(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	env.SeedAdmin(t, "admin@example.com", "CorrectHorse1Battery")
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	body, _ := json.Marshal(map[string]any{"instance_name": ""})
	rec := adminPatch(t, env, adminCookie, "/api/settings/general", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := resp["error"]; got != "INSTANCE_NAME_REQUIRED" {
		t.Fatalf("error code = %v, want %q", got, "INSTANCE_NAME_REQUIRED")
	}
}

// TestPatchSecurity_MultiField_AtomicAudits exercises the audit-in-tx
// pattern this handler establishes for T4 (tokens) and T5 (email): a
// single PATCH that touches two keys emits exactly two
// config.<key>.changed audit rows — one per dirty field — and leaves
// untouched fields without any audit noise. A follow-up no-op PATCH
// (same body) must write zero additional rows.
func TestPatchSecurity_MultiField_AtomicAudits(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	env.SeedAdmin(t, "admin@example.com", "CorrectHorse1Battery")
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	body, _ := json.Marshal(map[string]any{
		"password_min_length":   14,
		"lockout_duration_secs": 1800,
	})
	rec := adminPatch(t, env, adminCookie, "/api/settings/security", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", rec.Code, rec.Body.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var count int
	if err := env.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_logs
		WHERE event_type IN ('config.password_min_length.changed', 'config.lockout_duration_secs.changed')
	`).Scan(&count); err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if count != 2 {
		t.Fatalf("want 2 audit rows, got %d", count)
	}

	// Untouched fields must NOT have audit rows.
	var otherCount int
	if err := env.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_logs
		WHERE event_type LIKE 'config.%.changed'
		  AND event_type NOT IN ('config.password_min_length.changed', 'config.lockout_duration_secs.changed')
	`).Scan(&otherCount); err != nil {
		t.Fatalf("other-fields audit query: %v", err)
	}
	if otherCount != 0 {
		t.Fatalf("unexpected audit rows for untouched fields: %d", otherCount)
	}

	// Re-submitting the same body (no actual change) must NOT write new audit rows.
	rec2 := adminPatch(t, env, adminCookie, "/api/settings/security", body)
	if rec2.Code != http.StatusOK {
		t.Fatalf("no-op repeat: got %d, want 200: %s", rec2.Code, rec2.Body.String())
	}
	var totalCount int
	if err := env.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_logs WHERE event_type LIKE 'config.%.changed'`).Scan(&totalCount); err != nil {
		t.Fatalf("total audit query: %v", err)
	}
	if totalCount != 2 {
		t.Fatalf("no-op PATCH wrote extra audit rows; got %d, want 2", totalCount)
	}
}

// TestPatchSecurity_Validation_OutOfRange verifies the validator rejects
// a password_min_length below the 8-character floor. The field-level
// error code is wired to an i18n key on the frontend; we only check the
// HTTP status here because the specific code lives in model tests.
func TestPatchSecurity_Validation_OutOfRange(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	env.SeedAdmin(t, "admin@example.com", "CorrectHorse1Battery")
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	body, _ := json.Marshal(map[string]any{"password_min_length": 4})
	rec := adminPatch(t, env, adminCookie, "/api/settings/security", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

// TestPatchSecurity_UnknownField_Rejected ensures DisallowUnknownFields
// is in force — an attacker cannot sneak arbitrary instance_config keys
// in via the schema-typed payload.
func TestPatchSecurity_UnknownField_Rejected(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	env.SeedAdmin(t, "admin@example.com", "CorrectHorse1Battery")
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	body, _ := json.Marshal(map[string]any{"password_min_length": 14, "unknown_field": "nope"})
	rec := adminPatch(t, env, adminCookie, "/api/settings/security", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400 (DisallowUnknownFields): %s", rec.Code, rec.Body.String())
	}
}
