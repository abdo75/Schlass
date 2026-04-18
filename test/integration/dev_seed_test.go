//go:build integration

package integration

import (
	"testing"

	"github.com/abdo75/Schlass/internal/bootstrap"
)

// TestSeedDevClient_Happy — SCHLASS_DEV=1 + http public URL inserts a
// confidential dev client and is idempotent on re-call.
func TestSeedDevClient_Happy(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	if err := bootstrap.SeedDevClient(t.Context(), env.Pool, "1", "http://localhost:3000"); err != nil {
		t.Fatalf("SeedDevClient: %v", err)
	}

	var count int
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM clients WHERE name = 'dev-test-client'`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("want 1 seeded client, got %d", count)
	}

	// Second invocation is a no-op.
	if err := bootstrap.SeedDevClient(t.Context(), env.Pool, "1", "http://localhost:3000"); err != nil {
		t.Fatalf("second SeedDevClient: %v", err)
	}
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM clients WHERE name = 'dev-test-client'`).Scan(&count); err != nil {
		t.Fatalf("count after second call: %v", err)
	}
	if count != 1 {
		t.Fatalf("idempotence violated: got %d dev clients", count)
	}

	var clientType, authMethod, status string
	var grants, scopes, redirects []string
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT client_type, token_endpoint_auth_method, status,
		        allowed_grant_types, allowed_scopes, redirect_uris
		 FROM clients WHERE name = 'dev-test-client'`).
		Scan(&clientType, &authMethod, &status, &grants, &scopes, &redirects); err != nil {
		t.Fatalf("read seeded row: %v", err)
	}
	if clientType != "confidential" {
		t.Fatalf("client_type: %q", clientType)
	}
	if authMethod != "client_secret_post" {
		t.Fatalf("auth method: %q", authMethod)
	}
	if status != "active" {
		t.Fatalf("status: %q", status)
	}
	assertContains(t, grants, "authorization_code")
	assertContains(t, grants, "refresh_token")
	assertContains(t, scopes, "openid")
	assertContains(t, redirects, "http://localhost:3000/oidc/dev-callback")
}

// TestSeedDevClient_SkipsWhenDevUnset — no-op when SCHLASS_DEV != "1".
func TestSeedDevClient_SkipsWhenDevUnset(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	if err := bootstrap.SeedDevClient(t.Context(), env.Pool, "", "http://localhost:3000"); err != nil {
		t.Fatalf("SeedDevClient: %v", err)
	}
	var count int
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM clients WHERE name = 'dev-test-client'`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("want 0 rows without SCHLASS_DEV, got %d", count)
	}
}

// TestSeedDevClient_RefusesHTTPS — will not poison a prod-shaped DB.
func TestSeedDevClient_RefusesHTTPS(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	if err := bootstrap.SeedDevClient(t.Context(), env.Pool, "1", "https://idp.example.com"); err != nil {
		t.Fatalf("SeedDevClient: %v", err)
	}
	var count int
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM clients WHERE name = 'dev-test-client'`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("want 0 rows under https, got %d", count)
	}
}

func assertContains(t *testing.T, slice []string, want string) {
	t.Helper()
	for _, s := range slice {
		if s == want {
			return
		}
	}
	t.Fatalf("slice missing %q: %v", want, slice)
}
