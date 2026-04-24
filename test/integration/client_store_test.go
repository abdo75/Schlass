//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/abdo75/Schlass/internal/clients"
	"github.com/abdo75/Schlass/internal/crypto"
)

func TestClientStore_GetByIDAndVerifySecret(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	secret := "s0-secret-value"
	hash, err := crypto.HashPassword(secret)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	var id string
	err = env.Pool.QueryRow(ctx, `
		INSERT INTO clients (name, client_type, secret_hash, redirect_uris,
		  allowed_grant_types, allowed_scopes, token_endpoint_auth_method)
		VALUES ('t','confidential',$1,ARRAY['https://rp.example.com/cb'],
		  ARRAY['authorization_code','refresh_token'],
		  ARRAY['openid','profile','email','offline_access'],
		  'client_secret_post')
		RETURNING id
	`, hash).Scan(&id)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	s := clients.NewStore()
	c, err := s.GetByID(ctx, env.Pool, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if c.ClientType != "confidential" {
		t.Fatalf("type=%s", c.ClientType)
	}
	if len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != "https://rp.example.com/cb" {
		t.Fatalf("redirect_uris=%v", c.RedirectURIs)
	}

	ok, err := s.VerifySecret(ctx, env.Pool, id, secret)
	if err != nil || !ok {
		t.Fatalf("verify good secret: ok=%v err=%v", ok, err)
	}
	ok, _ = s.VerifySecret(ctx, env.Pool, id, "wrong")
	if ok {
		t.Fatal("verify bad secret should return false")
	}

	if !s.ValidateRedirectURI(c, "https://rp.example.com/cb") {
		t.Fatal("exact redirect_uri should validate")
	}
	if s.ValidateRedirectURI(c, "https://rp.example.com/cb/") {
		t.Fatal("trailing slash must NOT validate (exact match)")
	}
	if s.ValidateRedirectURI(c, "https://rp.example.com/OTHER") {
		t.Fatal("different path must NOT validate")
	}
}

func TestClientStore_DisabledClientReturnsNotFound(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	hash, _ := crypto.HashPassword("s")
	var id string
	_ = env.Pool.QueryRow(ctx, `
		INSERT INTO clients (name, client_type, secret_hash, redirect_uris,
		  allowed_grant_types, allowed_scopes, token_endpoint_auth_method, status)
		VALUES ('t','confidential',$1,ARRAY['https://rp.example.com/cb'],
		  ARRAY['authorization_code'], ARRAY['openid'],
		  'client_secret_post', 'disabled')
		RETURNING id
	`, hash).Scan(&id)

	s := clients.NewStore()
	_, err := s.GetByID(ctx, env.Pool, id)
	if err != clients.ErrClientNotFound {
		t.Fatalf("got %v want ErrClientNotFound (enumeration defense)", err)
	}
}

func TestClientStore_GetByIDMalformedUUIDReturnsNotFound(t *testing.T) {
	env := NewTestEnv(t)
	s := clients.NewStore()
	_, err := s.GetByID(context.Background(), env.Pool, "not-a-uuid")
	if err != clients.ErrClientNotFound {
		t.Fatalf("got %v want ErrClientNotFound", err)
	}
}
