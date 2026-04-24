//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/abdo75/Schlass/internal/audit"
	signingkeys "github.com/abdo75/Schlass/internal/signingkeys"
	"github.com/abdo75/Schlass/internal/oidc"
)

func TestBootstrapSigningKey_GeneratesWhenNoneActive(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()
	ctx := context.Background()

	s := signingkeys.NewStore()
	if _, err := s.GetActive(ctx, env.Pool); err == nil {
		t.Fatal("precondition: expected no active key in fresh DB")
	}

	auditStore := audit.NewStore()
	// Use a deterministic 32-byte KEK for this test.
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	if err := signingkeys.Bootstrap(ctx, env.Pool, auditStore, kek); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	got, err := s.GetActive(ctx, env.Pool)
	if err != nil {
		t.Fatalf("get active after bootstrap: %v", err)
	}
	if got.Status != "active" {
		t.Fatalf("status=%s want active", got.Status)
	}

	// Idempotency: second call is a no-op.
	if err := signingkeys.Bootstrap(ctx, env.Pool, auditStore, kek); err != nil {
		t.Fatalf("bootstrap 2nd call: %v", err)
	}
	keys, _ := s.ListPublishable(ctx, env.Pool)
	activeCount := 0
	for _, k := range keys {
		if k.Status == "active" {
			activeCount++
		}
	}
	if activeCount != 1 {
		t.Fatalf("expected 1 active key after 2 bootstraps, got %d", activeCount)
	}

	// Exactly one generated audit row.
	rows, _ := env.Pool.Query(ctx, `SELECT count(*) FROM audit_logs WHERE event_type='oidc.signing_key.generated'`)
	defer rows.Close()
	var count int
	if rows.Next() {
		_ = rows.Scan(&count)
	}
	if count != 1 {
		t.Fatalf("expected 1 signing_key.generated audit row, got %d", count)
	}

	// Private key round-trips (proves KEK encryption worked end-to-end).
	unwrapped, err := oidc.UnwrapPrivateKey(got.PrivateKeyEncrypted, kek)
	if err != nil {
		t.Fatalf("unwrap bootstrapped private key: %v", err)
	}
	if _, err := oidc.ParsePrivatePEM(unwrapped); err != nil {
		t.Fatalf("parse bootstrapped private key: %v", err)
	}
}
