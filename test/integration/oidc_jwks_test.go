//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abdo75/Schlass/internal/oidc"
	"github.com/abdo75/Schlass/internal/store"
)

func TestJWKS_PublishesBootstrappedActiveKey(t *testing.T) {
	env := NewTestEnv(t)

	if err := oidc.BootstrapSigningKey(context.Background(), env.Pool, store.NewAuditStore(), env.Cfg.EncryptionKey); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/jwk-set+json" {
		t.Fatalf("content-type=%s", ct)
	}
	if cors := rec.Header().Get("Access-Control-Allow-Origin"); cors != "*" {
		t.Fatalf("CORS=%s", cors)
	}
	var set oidc.JWKSet
	if err := json.NewDecoder(rec.Body).Decode(&set); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(set.Keys) < 1 {
		t.Fatalf("expected ≥1 JWK, got %d", len(set.Keys))
	}
	k := set.Keys[0]
	if k.Alg != "RS256" || k.Kty != "RSA" || k.Use != "sig" || k.Kid == "" || k.N == "" || k.E == "" {
		t.Fatalf("malformed JWK: %+v", k)
	}
}

func TestJWKS_RetiredKeysOmitted(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	s := store.NewSigningKeyStore()
	// An active + a retired key directly inserted.
	pubPEM, _, _ := oidc.GenerateKeyPair()
	activeID, _ := s.Insert(ctx, env.Pool, pubPEM, []byte("enc"), "active")
	retiredID, _ := s.Insert(ctx, env.Pool, pubPEM, []byte("enc2"), "retired")

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var set oidc.JWKSet
	_ = json.NewDecoder(rec.Body).Decode(&set)
	got := map[string]bool{}
	for _, k := range set.Keys {
		got[k.Kid] = true
	}
	if !got[activeID.String()] {
		t.Fatal("active key should be in JWKS")
	}
	if got[retiredID.String()] {
		t.Fatal("retired key should NOT be in JWKS")
	}
}
