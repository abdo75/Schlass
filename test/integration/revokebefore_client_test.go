//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/abdo75/Schlass/internal/revokebefore"
)

func TestRevokeBefore_ClientSetAndGet(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()
	clientID := "11111111-2222-3333-4444-555555555555"

	if _, err := revokebefore.ClientGet(ctx, env.ValkeyClient, clientID); !errors.Is(err, revokebefore.ErrNotSet) {
		t.Errorf("expected ErrNotSet, got %v", err)
	}

	if err := revokebefore.ClientSetNow(ctx, env.ValkeyClient, clientID); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := revokebefore.ClientGet(ctx, env.ValkeyClient, clientID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if time.Since(got) > 5*time.Second {
		t.Errorf("cutoff = %v, too far in past", got)
	}
}
