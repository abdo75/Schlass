// Package bootstrap holds startup-only helpers that run once during main()
// initialization — signing-key generation lives in internal/oidc;
// developer-mode client seeding lives here.
package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/crypto"
)

// devSeedClientName is the canonical name used to detect an already-seeded
// dev client. Idempotency key — if a row with this name exists, SeedDevClient
// is a no-op (beyond a log line).
const devSeedClientName = "dev-test-client"

// SeedDevClient inserts a single confidential OIDC client intended for local
// development and end-to-end tests. It refuses to run unless both:
//
//   - environment variable SCHLASS_DEV == "1"
//   - publicURL scheme is http (never https — refuses to poison a prod DB)
//
// The generated client_id is a new UUID; the client_secret defaults to 32
// random bytes base64url-encoded. A deterministic override is honored from
// the SCHLASS_DEV_SECRET env var — set in docker-compose.e2e.yml so
// Playwright knows the secret without scraping container logs. Secrets are
// Argon2id-hashed before storage; the plaintext is logged once at INFO.
//
// Upserts by name: if a dev-test-client row already exists, its
// redirect_uris / allowed_grant_types / allowed_scopes /
// token_endpoint_auth_method / status are refreshed in-place to match the
// values the code currently declares. The secret_hash is left alone on the
// update path, so a deterministic SCHLASS_DEV_SECRET set against a fresh
// volume continues to verify across container restarts. This shape lets a
// developer iterate on scopes/grants without wiping the DB volume.
func SeedDevClient(ctx context.Context, pool *pgxpool.Pool, dev, secretOverride, publicURL string) error {
	if dev != "1" {
		return nil
	}
	if strings.HasPrefix(publicURL, "https://") {
		slog.Warn("dev-seed refused: SCHLASS_PUBLIC_URL is https, skipping developer client insert",
			"public_url", publicURL)
		return nil
	}

	redirectURIs := []string{publicURL + "/oidc/dev-callback"}
	grantTypes := []string{"authorization_code", "refresh_token"}
	// offline_access is required so /token mints refresh_token on the
	// authorization_code grant — without it, refresh-flow testing is
	// impossible against the dev client.
	scopes := []string{"openid", "profile", "email", "offline_access"}

	var existingID uuid.UUID
	err := pool.QueryRow(ctx, `SELECT id FROM clients WHERE name = $1 LIMIT 1`, devSeedClientName).Scan(&existingID)
	if err == nil {
		// Refresh shape in-place. Secret untouched.
		if _, uerr := pool.Exec(ctx, `
			UPDATE clients SET
				redirect_uris = $1,
				allowed_grant_types = $2,
				allowed_scopes = $3,
				token_endpoint_auth_method = 'client_secret_post',
				status = 'active',
				updated_at = now()
			WHERE id = $4
		`, redirectURIs, grantTypes, scopes, existingID); uerr != nil {
			return fmt.Errorf("dev-seed: refresh existing: %w", uerr)
		}
		slog.Info("dev-seed: client already present, shape refreshed (secret unchanged)",
			"name", devSeedClientName, "client_id", existingID.String())
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("dev-seed: check existing: %w", err)
	}

	var secret string
	if secretOverride != "" {
		secret = secretOverride
	} else {
		var secretBuf [32]byte
		if _, err := rand.Read(secretBuf[:]); err != nil {
			return fmt.Errorf("dev-seed: generate secret: %w", err)
		}
		secret = base64.RawURLEncoding.EncodeToString(secretBuf[:])
	}
	secretHash, err := crypto.HashPassword(secret)
	if err != nil {
		return fmt.Errorf("dev-seed: hash secret: %w", err)
	}

	var clientID uuid.UUID
	err = pool.QueryRow(ctx, `
		INSERT INTO clients (
			name, client_type, secret_hash, redirect_uris,
			allowed_grant_types, allowed_scopes,
			token_endpoint_auth_method, status
		) VALUES ($1, 'confidential', $2, $3, $4, $5, 'client_secret_post', 'active')
		RETURNING id
	`, devSeedClientName, secretHash, redirectURIs, grantTypes, scopes).Scan(&clientID)
	if err != nil {
		return fmt.Errorf("dev-seed: insert client: %w", err)
	}

	// Plaintext secret is emitted exactly once — never written to the DB and
	// impossible to recover after startup. Developers who lose it must delete
	// the row and restart. The log call is intentionally INFO-level with
	// distinctive keys so it's easy to grep out of container logs.
	slog.Info("dev-seed: confidential OIDC client inserted",
		"name", devSeedClientName,
		"client_id", clientID.String(),
		"client_secret", secret,
		"redirect_uri", redirectURIs[0])
	return nil
}
