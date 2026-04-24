//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/abdo75/Schlass/internal/clients"
)

func TestClientStore_UpdateFields_Partial(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	c, err := clients.NewStore().Create(ctx, env.Pool, clients.CreateClientParams{
		Name: "before", ClientType: "confidential", SecretHash: "h",
		RedirectURIs:            []string{"https://a/cb"},
		AllowedGrantTypes:       []string{"authorization_code"},
		AllowedScopes:           []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_post",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	newName := "after"
	updated, err := clients.NewStore().UpdateFields(ctx, env.Pool, c.ID.String(), clients.UpdateClientPatch{
		Name: &newName,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "after" {
		t.Errorf("name = %q, want after", updated.Name)
	}
	// Other fields unchanged
	if len(updated.RedirectURIs) != 1 || updated.RedirectURIs[0] != "https://a/cb" {
		t.Errorf("redirect_uris changed unexpectedly: %v", updated.RedirectURIs)
	}
}
