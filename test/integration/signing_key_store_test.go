//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/abdo75/Schlass/internal/store"
)

func TestSigningKeyStore_InsertAndListPublishable(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	s := store.NewSigningKeyStore()
	ctx := context.Background()

	activeID, err := s.Insert(ctx, env.Pool, []byte("---PUB-ACT---"), []byte("enc-act"), "active")
	if err != nil {
		t.Fatalf("insert active: %v", err)
	}
	retiringID, err := s.Insert(ctx, env.Pool, []byte("---PUB-RET---"), []byte("enc-ret"), "retiring")
	if err != nil {
		t.Fatalf("insert retiring: %v", err)
	}
	retiredID, _ := s.Insert(ctx, env.Pool, []byte("---PUB-OLD---"), []byte("enc-old"), "retired")

	pub, err := s.ListPublishable(ctx, env.Pool)
	if err != nil {
		t.Fatalf("list publishable: %v", err)
	}
	if len(pub) != 2 {
		t.Fatalf("expected 2 publishable keys (active+retiring), got %d", len(pub))
	}
	ids := map[string]bool{pub[0].ID.String(): true, pub[1].ID.String(): true}
	if !ids[activeID.String()] || !ids[retiringID.String()] {
		t.Fatal("publishable missing expected keys")
	}
	if ids[retiredID.String()] {
		t.Fatal("retired key must not appear in publishable set")
	}
	// Active must come first.
	if pub[0].Status != "active" {
		t.Fatalf("ordering: first key status=%s want active", pub[0].Status)
	}
}

func TestSigningKeyStore_GetActive(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	s := store.NewSigningKeyStore()
	ctx := context.Background()

	if _, err := s.GetActive(ctx, env.Pool); err == nil {
		t.Fatal("GetActive on empty table should return error")
	}
	id, _ := s.Insert(ctx, env.Pool, []byte("pub"), []byte("enc"), "active")
	got, err := s.GetActive(ctx, env.Pool)
	if err != nil {
		t.Fatalf("get active: %v", err)
	}
	if got.ID != id {
		t.Fatal("wrong active key")
	}
}

func TestSigningKeyStore_MarkRetiringSetsRotatedAt(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	s := store.NewSigningKeyStore()
	ctx := context.Background()
	id, _ := s.Insert(ctx, env.Pool, []byte("pub"), []byte("enc"), "active")

	before := time.Now()
	if err := s.MarkRetiring(ctx, env.Pool, id); err != nil {
		t.Fatalf("mark retiring: %v", err)
	}
	keys, _ := s.ListPublishable(ctx, env.Pool)
	var found *store.SigningKey
	for _, k := range keys {
		if k.ID == id {
			found = k
		}
	}
	if found == nil {
		t.Fatal("retiring key missing from publishable")
	}
	if found.Status != "retiring" {
		t.Fatalf("status=%s want retiring", found.Status)
	}
	if found.RotatedAt == nil || found.RotatedAt.Before(before) {
		t.Fatal("rotated_at not set correctly")
	}
}

func TestSigningKeyStore_ListRetirableFiltersByRotatedAt(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	s := store.NewSigningKeyStore()
	ctx := context.Background()
	oldID, _ := s.Insert(ctx, env.Pool, []byte("pub-old"), []byte("enc-old"), "retiring")
	freshID, _ := s.Insert(ctx, env.Pool, []byte("pub-fresh"), []byte("enc-fresh"), "retiring")
	activeID, _ := s.Insert(ctx, env.Pool, []byte("pub-act"), []byte("enc-act"), "active")

	_, _ = env.Pool.Exec(ctx, `UPDATE signing_keys SET rotated_at = now() - interval '48 hours' WHERE id=$1`, oldID)
	_, _ = env.Pool.Exec(ctx, `UPDATE signing_keys SET rotated_at = now() WHERE id=$1`, freshID)

	cutoff := time.Now().Add(-24 * time.Hour)
	ids, err := s.ListRetirable(ctx, env.Pool, cutoff)
	if err != nil {
		t.Fatalf("list retirable: %v", err)
	}
	found := map[string]bool{}
	for _, id := range ids {
		found[id.String()] = true
	}
	if !found[oldID.String()] {
		t.Fatal("old retiring key should be retirable")
	}
	if found[freshID.String()] {
		t.Fatal("fresh retiring key should NOT be retirable")
	}
	if found[activeID.String()] {
		t.Fatal("active key should never be retirable")
	}
}

func TestSigningKeyStore_MarkRetired(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	s := store.NewSigningKeyStore()
	ctx := context.Background()
	id, _ := s.Insert(ctx, env.Pool, []byte("pub"), []byte("enc"), "retiring")
	if err := s.MarkRetired(ctx, env.Pool, id); err != nil {
		t.Fatalf("mark retired: %v", err)
	}
	pub, _ := s.ListPublishable(ctx, env.Pool)
	for _, k := range pub {
		if k.ID == id {
			t.Fatal("retired key still publishable")
		}
	}
}
