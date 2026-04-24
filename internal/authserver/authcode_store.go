// Package authserver implements the OIDC authorization-server endpoints
// (/authorize, /token, /userinfo, discovery) and the bearer-token middleware.
// Authorization code storage lives here because it is only accessed by this
// package's handlers — no other feature touches the authorization_codes table.
package authserver

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/abdo75/Schlass/internal/database"
)

type AuthCodeRow struct {
	CodeHash            string
	ClientID            uuid.UUID
	UserID              uuid.UUID
	RedirectURI         string
	Scopes              []string
	Nonce               *string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	FamilyID            uuid.UUID
}

// ErrAuthCodeAlreadyUsed collapses replay / expiry / unknown — caller
// response is identical. Replay detection uses LookupFamilyByCodeHash.
var ErrAuthCodeAlreadyUsed = errors.New("auth_code: already used, expired, or unknown")

type AuthCodeStore struct{}

func NewAuthCodeStore() *AuthCodeStore { return &AuthCodeStore{} }

func (s *AuthCodeStore) Insert(ctx context.Context, q database.Querier, row AuthCodeRow) error {
	_, err := q.Exec(ctx, `
		INSERT INTO authorization_codes
		  (code_hash, client_id, user_id, redirect_uri, scopes, nonce,
		   code_challenge, code_challenge_method, expires_at, family_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`, row.CodeHash, row.ClientID, row.UserID, row.RedirectURI, row.Scopes,
		row.Nonce, row.CodeChallenge, row.CodeChallengeMethod,
		row.ExpiresAt, row.FamilyID)
	return err
}

// ConsumeOnce atomically marks the code used via UPDATE...RETURNING.
// Missing, expired, already-used all collapse to ErrAuthCodeAlreadyUsed.
func (s *AuthCodeStore) ConsumeOnce(ctx context.Context, q database.Querier, codeHash string) (*AuthCodeRow, error) {
	var row AuthCodeRow
	err := q.QueryRow(ctx, `
		UPDATE authorization_codes
		SET used = true
		WHERE code_hash = $1 AND NOT used AND expires_at > now()
		RETURNING code_hash, client_id, user_id, redirect_uri, scopes,
		          nonce, code_challenge, code_challenge_method, expires_at, family_id
	`, codeHash).Scan(&row.CodeHash, &row.ClientID, &row.UserID, &row.RedirectURI,
		&row.Scopes, &row.Nonce, &row.CodeChallenge, &row.CodeChallengeMethod,
		&row.ExpiresAt, &row.FamilyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAuthCodeAlreadyUsed
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// LookupFamilyByCodeHash — replay detection after ConsumeOnce failed.
func (s *AuthCodeStore) LookupFamilyByCodeHash(ctx context.Context, q database.Querier, codeHash string) (uuid.UUID, error) {
	var id uuid.UUID
	err := q.QueryRow(ctx, `SELECT family_id FROM authorization_codes WHERE code_hash = $1`, codeHash).Scan(&id)
	return id, err
}
