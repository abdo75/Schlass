//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/abdo75/Schlass/internal/store"
)

func TestClientStore_List(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	// Seed: two active, one disabled.
	seed := func(name, status string) {
		_, err := env.Pool.Exec(ctx, `
			INSERT INTO clients (name, client_type, secret_hash, redirect_uris,
			  allowed_grant_types, allowed_scopes, token_endpoint_auth_method, status)
			VALUES ($1, 'confidential', 'hash', ARRAY['https://x/cb'],
			  ARRAY['authorization_code'], ARRAY['openid'], 'client_secret_post', $2)
		`, name, status)
		if err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	seed("a", "active")
	seed("b", "active")
	seed("c", "disabled")

	s := store.NewClientStore()

	active, err := s.List(ctx, env.Pool, "active")
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	if len(active) != 2 {
		t.Errorf("active: got %d, want 2", len(active))
	}

	disabled, err := s.List(ctx, env.Pool, "disabled")
	if err != nil {
		t.Fatalf("list disabled: %v", err)
	}
	if len(disabled) != 1 {
		t.Errorf("disabled: got %d, want 1", len(disabled))
	}

	all, err := s.List(ctx, env.Pool, "all")
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("all: got %d, want 3", len(all))
	}
}
