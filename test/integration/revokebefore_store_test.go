//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/abdo75/Schlass/internal/revokebefore"
)

func TestRevokeBefore_SetAndGetRoundTrip(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()
	userID := uuid.NewString()

	// Get before set → ErrNotSet
	if _, err := revokebefore.Get(ctx, env.ValkeyClient, userID); err != revokebefore.ErrNotSet {
		t.Fatalf("want ErrNotSet, got %v", err)
	}

	target := time.Now().UTC().Truncate(time.Second)
	if err := revokebefore.Set(ctx, env.ValkeyClient, userID, target); err != nil {
		t.Fatalf("set: %v", err)
	}

	got, err := revokebefore.Get(ctx, env.ValkeyClient, userID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.Equal(target) {
		t.Fatalf("got=%v want=%v", got, target)
	}
}

func TestRevokeBefore_OverwriteLatestWins(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()
	userID := uuid.NewString()

	first := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Second)
	second := time.Now().UTC().Truncate(time.Second)

	_ = revokebefore.Set(ctx, env.ValkeyClient, userID, first)
	_ = revokebefore.Set(ctx, env.ValkeyClient, userID, second)

	got, _ := revokebefore.Get(ctx, env.ValkeyClient, userID)
	if !got.Equal(second) {
		t.Fatalf("latest write should win; got=%v want=%v", got, second)
	}
}

func TestRevokeBefore_TTLPreservedForAtLeast24Hours(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()
	userID := uuid.NewString()

	_ = revokebefore.Set(ctx, env.ValkeyClient, userID, time.Now().UTC())
	ttl, _ := env.ValkeyClient.TTL(ctx, "user:revoke_before:"+userID).Result()
	if ttl < 24*time.Hour {
		t.Fatalf("ttl should be ≥24h; got %v", ttl)
	}
	if ttl > 31*24*time.Hour {
		t.Fatalf("ttl should be ≤31d; got %v", ttl)
	}
}
