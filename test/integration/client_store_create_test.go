//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/abdo75/Schlass/internal/store"
)

func TestClientStore_Create(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	// Seed a creator user
	var creatorID uuid.UUID
	err := env.Pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, role, status)
		VALUES ('admin@x', 'h', 'super_admin', 'active')
		RETURNING id
	`).Scan(&creatorID)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	s := store.NewClientStore()
	c, err := s.Create(ctx, env.Pool, store.CreateClientParams{
		Name:                    "customer-portal",
		ClientType:              "confidential",
		SecretHash:              "argon2-hash",
		RedirectURIs:            []string{"https://x.com/cb"},
		AllowedGrantTypes:       []string{"authorization_code", "refresh_token"},
		AllowedScopes:           []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_post",
		CreatedByUserID:         &creatorID,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if c.Name != "customer-portal" {
		t.Errorf("name = %q, want customer-portal", c.Name)
	}
	if c.Status != "active" {
		t.Errorf("status = %q, want active", c.Status)
	}
	if c.CreatedByUserID == nil || *c.CreatedByUserID != creatorID {
		t.Errorf("created_by_user_id mismatch")
	}
}
