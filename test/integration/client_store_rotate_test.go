//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/abdo75/Schlass/internal/store"
)

func TestClientStore_RotateSecret_OverlapWindow(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	s := store.NewClientStore()
	c, err := s.Create(ctx, env.Pool, store.CreateClientParams{
		Name: "r", ClientType: "confidential", SecretHash: "old-hash",
		RedirectURIs:            []string{"https://x/cb"},
		AllowedGrantTypes:       []string{"authorization_code"},
		AllowedScopes:           []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_post",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	rotated, err := s.RotateSecret(ctx, env.Pool, c.ID.String(), "new-hash", 24*time.Hour)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rotated.SecretHash == nil || *rotated.SecretHash != "new-hash" {
		t.Errorf("secret_hash: got %v, want new-hash", rotated.SecretHash)
	}
	if rotated.SecretHashPrevious == nil || *rotated.SecretHashPrevious != "old-hash" {
		t.Errorf("secret_hash_previous: got %v, want old-hash", rotated.SecretHashPrevious)
	}
	if rotated.SecretPreviousExpiresAt == nil {
		t.Fatal("secret_previous_expires_at is nil")
	}
	if time.Until(*rotated.SecretPreviousExpiresAt) < 23*time.Hour {
		t.Errorf("previous_expires_at = %v, expected ~24h from now", rotated.SecretPreviousExpiresAt)
	}

	// Second rotation discards the first previous.
	rotated2, err := s.RotateSecret(ctx, env.Pool, c.ID.String(), "newer-hash", 24*time.Hour)
	if err != nil {
		t.Fatalf("second rotate: %v", err)
	}
	if *rotated2.SecretHashPrevious != "new-hash" {
		t.Errorf("after 2nd rotate: previous should be 'new-hash', got %q", *rotated2.SecretHashPrevious)
	}
}
