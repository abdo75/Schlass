package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/abdo75/Schlass/internal/session"
)

func TestSessionStore_CreateGetDelete(t *testing.T) {
	ctx := context.Background()
	env := NewTestEnv(t)

	store := session.NewValkeyStore(env.ValkeyClient, 24*time.Hour)

	// Create
	token, err := store.Create(ctx, "11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if len(token) < 40 {
		t.Fatalf("token too short: %q", token)
	}

	// Get returns the session
	got, err := store.Get(ctx, token)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.UserID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("user_id mismatch: got %q", got.UserID)
	}

	// Delete removes it
	if err := store.Delete(ctx, token); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Get after Delete returns ErrNotFound
	_, err = store.Get(ctx, token)
	if !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// Delete is idempotent — deleting a missing key is not an error.
	if err := store.Delete(ctx, token); err != nil {
		t.Fatalf("Delete of missing key should be idempotent, got %v", err)
	}
}

func TestSessionStore_SlidingTTL(t *testing.T) {
	ctx := context.Background()
	env := NewTestEnv(t)

	// 5-second TTL with 2-second margins: comfortable for CI
	store := session.NewValkeyStore(env.ValkeyClient, 5*time.Second)

	token, err := store.Create(ctx, "22222222-2222-2222-2222-222222222222")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Sleep 3 seconds, then Get — should succeed and slide TTL back to 5s.
	time.Sleep(3 * time.Second)
	if _, err := store.Get(ctx, token); err != nil {
		t.Fatalf("Get during TTL failed: %v", err)
	}

	// Sleep another 3 seconds — total 6 seconds, which would have expired
	// without the slide (2s past the absolute TTL), but the slide at t=3s
	// reset us to t=3+5=8s, so we're still alive at t=6s with 2s to spare.
	time.Sleep(3 * time.Second)
	if _, err := store.Get(ctx, token); err != nil {
		t.Fatalf("Get after slide failed: %v", err)
	}

	// Now stop touching it and let it expire. Wait 6 seconds past the last
	// slide (at t=6s, slid to t=6+5=11s) so we're at t=12s with 1s of
	// margin past expiry. 6s is enough to avoid timing races but doesn't
	// drag the test out too long.
	time.Sleep(6 * time.Second)
	_, err = store.Get(ctx, token)
	if !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after TTL expiry, got %v", err)
	}
}
