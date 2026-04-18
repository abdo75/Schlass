//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abdo75/Schlass/internal/oidc"
)

func TestDiscoveryEndpoint_Shape(t *testing.T) {
	env := NewTestEnv(t)

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type=%s", ct)
	}
	if cors := rec.Header().Get("Access-Control-Allow-Origin"); cors != "*" {
		t.Fatalf("CORS=%s", cors)
	}
	if cache := rec.Header().Get("Cache-Control"); cache == "" {
		t.Fatalf("Cache-Control missing")
	}
	var got oidc.DiscoveryMetadata
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Issuer == "" || got.AuthorizationEndpoint == "" || got.JWKSURI == "" {
		t.Fatalf("missing fields: %+v", got)
	}
	// Issuer must match the test harness publicURL.
	if got.Issuer != "http://localhost:3000" {
		t.Fatalf("issuer=%s want http://localhost:3000", got.Issuer)
	}
}
