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

// Bootstrap + rotate through HTTP. Verifies:
//   - new active key is created
//   - previous active is now retiring
//   - oidc.signing_key.rotated audit row exists
func TestRotateSigningKey_TransitionsActiveToRetiringAndCreatesNew(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	// Bootstrap a key so there's an active one to rotate FROM.
	if err := oidc.BootstrapSigningKey(ctx, env.Pool, store.NewAuditStore(), env.Cfg.EncryptionKey); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	before, err := store.NewSigningKeyStore().GetActive(ctx, env.Pool)
	if err != nil {
		t.Fatalf("precondition: no active key: %v", err)
	}

	env.SeedAdmin(t, "admin@example.com", "CorrectHorse1Battery")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/admin/signing-keys/rotate", bytes.NewReader(nil))
	req.Header.Set("Origin", "http://localhost:3000")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d want 204: %s", rec.Code, rec.Body.String())
	}

	after, err := store.NewSigningKeyStore().GetActive(ctx, env.Pool)
	if err != nil {
		t.Fatalf("no active key after rotate: %v", err)
	}
	if after.ID == before.ID {
		t.Fatal("rotate did not generate a new active key")
	}

	pub, _ := store.NewSigningKeyStore().ListPublishable(ctx, env.Pool)
	foundRetiring := false
	for _, k := range pub {
		if k.ID == before.ID && k.Status == "retiring" {
			foundRetiring = true
		}
	}
	if !foundRetiring {
		t.Fatal("previous active key should be retiring")
	}

	// Audit assertion.
	var count int
	row := env.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE event_type='oidc.signing_key.rotated'`)
	_ = row.Scan(&count)
	if count != 1 {
		t.Fatalf("expected 1 rotated audit row, got %d", count)
	}
}

// Non-admin users receive 403 (permission gate).
func TestRotateSigningKey_RejectsNonSuperAdmin(t *testing.T) {
	env := NewTestEnv(t)

	// Admin to seed + create non-admin.
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse1Battery")
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	createBody := bytes.NewBufferString(`{"email":"user@example.com","role":"user"}`)
	createReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/users", createBody)
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Origin", "http://localhost:3000")
	createReq.AddCookie(adminCookie)
	createRec := httptest.NewRecorder()
	env.Router.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create user: %d", createRec.Code)
	}
	var cr struct {
		TemporaryPassword string `json:"temporary_password"`
	}
	_ = json.NewDecoder(createRec.Body).Decode(&cr)

	// Login as non-admin with temp password.
	userCookie := env.LoginAsAdmin(t, "user@example.com", cr.TemporaryPassword)

	// Complete forced password change.
	chBody, _ := json.Marshal(map[string]string{
		"current_password": cr.TemporaryPassword,
		"new_password":     "NewPassword1Battery",
	})
	chReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/change-password", bytes.NewReader(chBody))
	chReq.Header.Set("Content-Type", "application/json")
	chReq.Header.Set("Origin", "http://localhost:3000")
	chReq.AddCookie(userCookie)
	chRec := httptest.NewRecorder()
	env.Router.ServeHTTP(chRec, chReq)
	if chRec.Code != http.StatusOK {
		t.Fatalf("change-password: %d: %s", chRec.Code, chRec.Body.String())
	}

	// Log in again with the new password to get a usable session.
	userCookie = env.LoginAsAdmin(t, "user@example.com", "NewPassword1Battery")

	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/admin/signing-keys/rotate", bytes.NewReader(nil))
	req.Header.Set("Origin", "http://localhost:3000")
	req.AddCookie(userCookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403: %s", rec.Code, rec.Body.String())
	}
}
