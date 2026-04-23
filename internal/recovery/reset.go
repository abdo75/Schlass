// Package recovery implements the `schlass recovery-reset` CLI subcommand.
// Gated by SCHLASS_RECOVERY_MODE=1; refuses on non-super_admin targets.
// Only sanctioned path to reset a super_admin password when no other admin
// is available (email reset is blocked for super_admin — see CLAUDE.md).
package recovery

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/auth"
	"github.com/abdo75/Schlass/internal/config"
	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/users"
)

const tokenTTL = time.Hour

// Run parses flags + executes. Intended entry from cmd/schlass subcommand
// dispatch. Returns non-nil error on any failure; main prints + exits 1.
func Run(args []string) error {
	fs := flag.NewFlagSet("recovery-reset", flag.ContinueOnError)
	email := fs.String("email", "", "admin email to issue a recovery token for (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" {
		return errors.New("recovery-reset: --email is required")
	}
	if os.Getenv("SCHLASS_RECOVERY_MODE") != "1" {
		return errors.New("recovery-reset: SCHLASS_RECOVERY_MODE=1 is required (operator-level access gate)")
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("recovery-reset: load config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("recovery-reset: connect db: %w", err)
	}
	defer pool.Close()

	return Execute(ctx, pool, cfg, strings.ToLower(strings.TrimSpace(*email)), os.Stdout)
}

// Execute is the testable core — no global state, no Exit. Tests call this
// directly with a fake stdout. Run() is the CLI entry point that loads
// config + opens the pool; Execute() reuses those.
func Execute(ctx context.Context, pool *pgxpool.Pool, cfg *config.Env, email string, stdout interface {
	Write(p []byte) (int, error)
}) error {
	userStore := users.NewStore()
	u, err := userStore.GetByEmail(ctx, pool, email)
	if err != nil {
		return fmt.Errorf("recovery-reset: lookup user: %w", err)
	}
	if u.Role != "super_admin" {
		return fmt.Errorf("recovery-reset: target %s is not a super_admin (role=%s); refusing", email, u.Role)
	}

	pepper, err := crypto.DeriveTokenPepper(cfg.EncryptionKey)
	if err != nil {
		return fmt.Errorf("recovery-reset: derive pepper: %w", err)
	}
	tokenStore := auth.NewTokenStore(pepper)

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Errorf("recovery-reset: rand: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(raw[:])

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("recovery-reset: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tokenID, err := tokenStore.Insert(ctx, tx, u.ID, plaintext, tokenTTL, netip.Addr{})
	if err != nil {
		return fmt.Errorf("recovery-reset: insert token: %w", err)
	}

	auditStore := audit.NewStore()
	if err := auditStore.Log(ctx, tx, audit.Entry{
		EventType:  "password_reset.recovery_issued",
		ActorEmail: "system:recovery",
		TargetType: "user",
		TargetID:   u.ID.String(),
		Outcome:    "success",
		Metadata: map[string]any{
			"token_id":     tokenID.String(),
			"target_email": u.Email,
			"invoker":      invokerInfo(),
		},
	}); err != nil {
		return fmt.Errorf("recovery-reset: audit: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("recovery-reset: commit: %w", err)
	}

	// Intentionally the ONLY stdout write. Callers capture just this line.
	if _, err := fmt.Fprintf(stdout, "Reset URL: %s/reset-password/%s\n", strings.TrimRight(cfg.SchlassPublicURL, "/"), plaintext); err != nil {
		return fmt.Errorf("recovery-reset: write stdout: %w", err)
	}
	return nil
}

// invokerInfo best-effort captures hostname + OS user for forensics. Never
// fails — missing fields become empty strings in the audit metadata.
func invokerInfo() map[string]string {
	host, _ := os.Hostname()
	return map[string]string{
		"hostname": host,
		"os_user":  os.Getenv("USER"),
	}
}
