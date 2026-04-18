//go:build integration

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

	const userID = "11111111-1111-1111-1111-111111111111"

	// Create
	token, err := store.Create(ctx, userID, "192.0.2.1", "test-agent/1.0")
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
	if got.UserID != userID {
		t.Fatalf("user_id mismatch: got %q", got.UserID)
	}

	// Delete removes it
	if err := store.Delete(ctx, userID, token); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Get after Delete returns ErrNotFound
	_, err = store.Get(ctx, token)
	if !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// Delete is idempotent — deleting a missing key is not an error.
	if err := store.Delete(ctx, userID, token); err != nil {
		t.Fatalf("Delete of missing key should be idempotent, got %v", err)
	}
}

func TestSessionStore_SlidingTTL(t *testing.T) {
	ctx := context.Background()
	env := NewTestEnv(t)

	// 5-second TTL with 2-second margins: comfortable for CI
	store := session.NewValkeyStore(env.ValkeyClient, 5*time.Second)

	token, err := store.Create(ctx, "22222222-2222-2222-2222-222222222222", "192.0.2.2", "test-agent/1.0")
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

func TestSessionStore_MetadataRoundTrip(t *testing.T) {
	ctx := context.Background()
	env := NewTestEnv(t)

	store := session.NewValkeyStore(env.ValkeyClient, 30*time.Second)

	token, err := store.Create(ctx, "u1", "203.0.113.5", "Mozilla/5.0 Test")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.Get(ctx, token)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.UserID != "u1" {
		t.Fatalf("UserID: got %q", got.UserID)
	}
	if got.IPAddress != "203.0.113.5" {
		t.Fatalf("IPAddress: got %q", got.IPAddress)
	}
	if got.UserAgent != "Mozilla/5.0 Test" {
		t.Fatalf("UserAgent: got %q", got.UserAgent)
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("CreatedAt not set")
	}
	if got.LastSeenAt.Before(got.CreatedAt) {
		t.Fatalf("LastSeenAt (%v) before CreatedAt (%v)", got.LastSeenAt, got.CreatedAt)
	}

	// Second Get should advance LastSeenAt — this is the load-bearing
	// guarantee for the admin UI's "last seen X ago" column. A regression
	// that stores LastSeenAt on Create but never updates it on Get would
	// pass the first-Get assertions above but fail this one.
	firstLastSeen := got.LastSeenAt
	time.Sleep(10 * time.Millisecond)
	got2, err := store.Get(ctx, token)
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if !got2.LastSeenAt.After(firstLastSeen) {
		t.Fatalf("expected LastSeenAt to advance on second Get; first=%v second=%v",
			firstLastSeen, got2.LastSeenAt)
	}
}

func TestSessionStore_ListByUser(t *testing.T) {
	ctx := context.Background()
	env := NewTestEnv(t)
	store := session.NewValkeyStore(env.ValkeyClient, 30*time.Second)

	t1, err := store.Create(ctx, "u1", "1.1.1.1", "dev-A")
	if err != nil {
		t.Fatalf("Create t1: %v", err)
	}
	t2, err := store.Create(ctx, "u1", "2.2.2.2", "dev-B")
	if err != nil {
		t.Fatalf("Create t2: %v", err)
	}
	if _, err := store.Create(ctx, "u2", "3.3.3.3", "other-user"); err != nil {
		t.Fatalf("Create u2 session: %v", err)
	}

	sessions, err := store.ListByUser(ctx, "u1")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions for u1, got %d", len(sessions))
	}
	gotIPs := map[string]bool{}
	gotTokens := map[string]bool{}
	for _, s := range sessions {
		if s.Token == "" {
			t.Fatalf("expected non-empty Token on returned session, got %+v", s)
		}
		gotTokens[s.Token] = true
		gotIPs[s.IPAddress] = true
	}
	if !gotIPs["1.1.1.1"] || !gotIPs["2.2.2.2"] {
		t.Fatalf("missing expected IPs: %v", gotIPs)
	}
	if !gotTokens[t1] || !gotTokens[t2] {
		t.Fatalf("missing expected tokens: got %v want %v + %v", gotTokens, t1, t2)
	}

	// Cleanup with DeleteAllForUser
	if err := store.DeleteAllForUser(ctx, "u1"); err != nil {
		t.Fatalf("DeleteAllForUser: %v", err)
	}
	after, _ := store.ListByUser(ctx, "u1")
	if len(after) != 0 {
		t.Fatalf("expected 0 after DeleteAllForUser, got %d", len(after))
	}

	// u2 still has their session — confirm isolation.
	u2Sessions, _ := store.ListByUser(ctx, "u2")
	if len(u2Sessions) != 1 {
		t.Fatalf("expected u2's session intact, got %d", len(u2Sessions))
	}
}

func TestSessionStore_ListByUser_SkipsStaleEntries(t *testing.T) {
	ctx := context.Background()
	env := NewTestEnv(t)

	// Very short TTL so we can deterministically wait for expiry.
	store := session.NewValkeyStore(env.ValkeyClient, 1*time.Second)

	short, err := store.Create(ctx, "u-stale", "1.1.1.1", "short-lived")
	if err != nil {
		t.Fatalf("Create short: %v", err)
	}

	// Wait for the session key to expire but the user_sessions SET to
	// still exist. SET TTL == session TTL == 1s in this test env, so both
	// will expire around the same time — but SMEMBERS returns the token
	// as long as the SET itself hasn't expired yet. In practice both
	// expire within the same tick, so we explicitly re-add the token to
	// the SET to simulate the stale-entry case deterministically.
	time.Sleep(1500 * time.Millisecond)

	// Force the stale-entry case: re-SADD the expired token into a fresh
	// SET so SMEMBERS returns it even though the session key is gone.
	if err := env.ValkeyClient.SAdd(ctx, "user_sessions:u-stale", short).Err(); err != nil {
		t.Fatalf("SAdd stale token: %v", err)
	}
	// Also create a live session for the same user so ListByUser has
	// something real to return.
	live, _ := store.Create(ctx, "u-stale", "2.2.2.2", "live")

	// ListByUser should filter out the stale entry and return only the
	// live session — no error.
	sessions, err := store.ListByUser(ctx, "u-stale")
	if err != nil {
		t.Fatalf("ListByUser with stale entry: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 live session, got %d", len(sessions))
	}
	if sessions[0].Token != live {
		t.Fatalf("expected live token, got %q", sessions[0].Token)
	}
	if sessions[0].IPAddress != "2.2.2.2" {
		t.Fatalf("expected live IP, got %q", sessions[0].IPAddress)
	}
}
