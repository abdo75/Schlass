package signingkeys

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/oidc"
)

// Bootstrap is idempotent: no-op when an active key exists. Failure is
// fatal — refuse to serve without a signing key.
func Bootstrap(
	ctx context.Context,
	pool *pgxpool.Pool,
	auditStore audit.Logger,
	encryptionKey []byte,
) error {
	s := NewStore()
	if _, err := s.GetActive(ctx, pool); err == nil {
		return nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("bootstrap: check active: %w", err)
	}

	pubPEM, privPEM, err := oidc.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("bootstrap: generate keypair: %w", err)
	}
	wrapped, err := oidc.WrapPrivateKey(privPEM, encryptionKey)
	if err != nil {
		return fmt.Errorf("bootstrap: wrap private key: %w", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("bootstrap: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	id, err := s.Insert(ctx, tx, pubPEM, wrapped, "active")
	if err != nil {
		return fmt.Errorf("bootstrap: insert: %w", err)
	}
	if err := auditStore.Log(ctx, tx, audit.Entry{
		EventType:  "oidc.signing_key.generated",
		ActorEmail: "",
		TargetType: "signing_key",
		TargetID:   id.String(),
		Outcome:    "success",
		Metadata:   map[string]any{"algorithm": "RS256", "key_size_bits": oidc.RSAKeyBits},
	}); err != nil {
		return fmt.Errorf("bootstrap: audit: %w", err)
	}
	return tx.Commit(ctx)
}

// RetireSweep: cutoff must be at least AT-TTL + refresh-TTL + clock-skew in
// the past, otherwise tokens signed by the key could still be in flight when
// we stop publishing it.
func RetireSweep(
	ctx context.Context,
	pool *pgxpool.Pool,
	auditStore audit.Logger,
	cutoff time.Time,
) error {
	s := NewStore()
	ids, err := s.ListRetirable(ctx, pool, cutoff)
	if err != nil {
		return fmt.Errorf("retire sweep: list: %w", err)
	}
	for _, id := range ids {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("retire sweep: begin: %w", err)
		}
		if err := s.MarkRetired(ctx, tx, id); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("retire sweep: mark: %w", err)
		}
		if err := auditStore.Log(ctx, tx, audit.Entry{
			EventType:  "oidc.signing_key.retired",
			ActorEmail: "",
			TargetType: "signing_key",
			TargetID:   id.String(),
			Outcome:    "success",
		}); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("retire sweep: audit: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("retire sweep: commit: %w", err)
		}
	}
	return nil
}
