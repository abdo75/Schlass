//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/abdo75/Schlass/internal/clients"
)

func TestClientStore_DisableEnableDelete(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()
	s := clients.NewStore()

	c, err := s.Create(ctx, env.Pool, clients.CreateClientParams{
		Name: "l", ClientType: "confidential", SecretHash: "h",
		RedirectURIs:            []string{"https://x/cb"},
		AllowedGrantTypes:       []string{"authorization_code"},
		AllowedScopes:           []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_post",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := s.Disable(ctx, env.Pool, c.ID.String()); err != nil {
		t.Fatalf("disable: %v", err)
	}
	got, err := s.GetByIDAny(ctx, env.Pool, c.ID.String())
	if err != nil {
		t.Fatalf("get after disable: %v", err)
	}
	if got.Status != "disabled" {
		t.Errorf("status = %q, want disabled", got.Status)
	}
	if got.DisabledAt == nil {
		t.Errorf("disabled_at is nil")
	}

	if err := s.Enable(ctx, env.Pool, c.ID.String()); err != nil {
		t.Fatalf("enable: %v", err)
	}
	got, _ = s.GetByIDAny(ctx, env.Pool, c.ID.String())
	if got.Status != "active" {
		t.Errorf("after enable: status = %q, want active", got.Status)
	}
	if got.DisabledAt != nil {
		t.Errorf("after enable: disabled_at = %v, want nil", got.DisabledAt)
	}

	if err := s.Delete(ctx, env.Pool, c.ID.String()); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err = s.GetByIDAny(ctx, env.Pool, c.ID.String())
	if !errors.Is(err, clients.ErrClientNotFound) {
		t.Errorf("after delete: err = %v, want ErrClientNotFound", err)
	}
}
