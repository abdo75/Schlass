// Package server creates a test OIDC client at startup for local dev and
// end-to-end tests. Only runs when SCHLASS_DEV=1, and skips if the public URL
// uses https so it can never touch a production database. Safe to run again:
// refreshes the redirect URLs, grants, and scopes, but keeps the existing
// secret so a pinned SCHLASS_DEV_SECRET still works after a restart.
package server

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

const devSeedClientName = "dev-test-client"

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
	scopes := []string{"openid", "profile", "email", "offline_access"}

	var existingID uuid.UUID
	err := pool.QueryRow(ctx, `SELECT id FROM clients WHERE name = $1 LIMIT 1`, devSeedClientName).Scan(&existingID)
	if err == nil {
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

	slog.Info("dev-seed: confidential OIDC client inserted",
		"name", devSeedClientName,
		"client_id", clientID.String(),
		"client_secret", secret,
		"redirect_uri", redirectURIs[0])
	return nil
}
