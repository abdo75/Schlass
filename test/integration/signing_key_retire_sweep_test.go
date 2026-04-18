//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/abdo75/Schlass/internal/oidc"
	"github.com/abdo75/Schlass/internal/store"
)

func TestRetireSweep_RetiresOldRetiringKeys(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()
	ctx := context.Background()

	s := store.NewSigningKeyStore()
	oldID, _ := s.Insert(ctx, env.Pool, []byte("pub-old"), []byte("enc-old"), "retiring")
	freshID, _ := s.Insert(ctx, env.Pool, []byte("pub-fresh"), []byte("enc-fresh"), "retiring")

	_, _ = env.Pool.Exec(ctx, `UPDATE signing_keys SET rotated_at = now() - interval '48 hours' WHERE id=$1`, oldID)
	_, _ = env.Pool.Exec(ctx, `UPDATE signing_keys SET rotated_at = now() WHERE id=$1`, freshID)

	cutoff := time.Now().Add(-(15*time.Minute + 24*time.Hour + 30*time.Second))
	if err := oidc.RetireSweep(ctx, env.Pool, store.NewAuditStore(), cutoff); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	pub, _ := s.ListPublishable(ctx, env.Pool)
	for _, k := range pub {
		if k.ID == oldID {
			t.Fatalf("old key still publishable, expected retired")
		}
	}
	foundFresh := false
	for _, k := range pub {
		if k.ID == freshID {
			foundFresh = true
		}
	}
	if !foundFresh {
		t.Fatal("fresh retiring key should still be publishable")
	}

	// Retired audit row for oldID only.
	rows, _ := env.Pool.Query(ctx, `SELECT count(*) FROM audit_logs WHERE event_type='oidc.signing_key.retired'`)
	defer rows.Close()
	var count int
	if rows.Next() {
		_ = rows.Scan(&count)
	}
	if count != 1 {
		t.Fatalf("expected 1 retired audit row, got %d", count)
	}
}
