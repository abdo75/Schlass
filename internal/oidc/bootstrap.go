package oidc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/database"
	"github.com/abdo75/Schlass/internal/store"
)

// AuditLogger is the narrow interface bootstrap needs — matches handler.AuditLogger
// so *store.AuditStore satisfies it.
type AuditLogger interface {
	Log(ctx context.Context, q database.Querier, entry store.AuditEntry) error
}

// BootstrapSigningKey generates an active RSA signing key if none exists.
// Idempotent: subsequent calls are no-ops when an active key is already
// present. Writes oidc.signing_key.generated audit inside the same tx as the
// INSERT (system actor; actor_email empty).
//
// Called from main.go after RunMigrations. Failure is fatal — refuse to serve
// without a signing key.
func BootstrapSigningKey(
	ctx context.Context,
	pool *pgxpool.Pool,
	auditStore AuditLogger,
	encryptionKey []byte,
) error {
	s := store.NewSigningKeyStore()
	if _, err := s.GetActive(ctx, pool); err == nil {
		return nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("bootstrap: check active: %w", err)
	}

	pubPEM, privPEM, err := GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("bootstrap: generate keypair: %w", err)
	}
	wrapped, err := WrapPrivateKey(privPEM, encryptionKey)
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
	if err := auditStore.Log(ctx, tx, store.AuditEntry{
		EventType:  "oidc.signing_key.generated",
		ActorEmail: "",
		TargetType: "signing_key",
		TargetID:   id.String(),
		Outcome:    "success",
		Metadata:   map[string]any{"algorithm": "RS256", "key_size_bits": rsaKeyBits},
	}); err != nil {
		return fmt.Errorf("bootstrap: audit: %w", err)
	}
	return tx.Commit(ctx)
}

// RetireSweep transitions retiring keys older than cutoff to status=retired.
// Called at startup and immediately after every rotate. cutoff must be at
// least accessTTL + refreshTTL + clockSkew in the past — otherwise tokens
// signed by the key could still be in flight when we stop publishing it.
func RetireSweep(
	ctx context.Context,
	pool *pgxpool.Pool,
	auditStore AuditLogger,
	cutoff time.Time,
) error {
	s := store.NewSigningKeyStore()
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
		if err := auditStore.Log(ctx, tx, store.AuditEntry{
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
