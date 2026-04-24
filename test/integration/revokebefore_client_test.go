//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/abdo75/Schlass/internal/session"
)

func TestRevokeBefore_ClientSetAndGet(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()
	clientID := "11111111-2222-3333-4444-555555555555"

	if _, err := session.RevokeBeforeClientGet(ctx, env.ValkeyClient, clientID); !errors.Is(err, session.ErrRevokeBeforeNotSet) {
		t.Errorf("expected ErrNotSet, got %v", err)
	}

	if err := session.RevokeBeforeClientSetNow(ctx, env.ValkeyClient, clientID); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := session.RevokeBeforeClientGet(ctx, env.ValkeyClient, clientID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if time.Since(got) > 5*time.Second {
		t.Errorf("cutoff = %v, too far in past", got)
	}
}
