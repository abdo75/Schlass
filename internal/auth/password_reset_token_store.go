// Package auth handles the self-service password reset flow:
// token mint, HMAC-peppered storage, single-use validation, and confirm.
package auth

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/database"
)

var ErrResetTokenNotFound = errors.New("password reset token not found")

type PasswordResetToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// TokenStore holds the HMAC pepper used to hash plaintext
// tokens before storage. Pepper is HKDF-derived from SCHLASS_ENCRYPTION_KEY
// at startup — deterministic, so no persistence needed.
type TokenStore struct {
	pepper []byte
}

func NewTokenStore(pepper []byte) *TokenStore {
	if len(pepper) != 32 {
		panic("password_reset_token_store: pepper must be 32 bytes")
	}
	return &TokenStore{pepper: pepper}
}

// Insert stores HMAC-SHA256(pepper, plaintext). Plaintext never touches the DB.
func (s *TokenStore) Insert(ctx context.Context, q database.Querier, userID uuid.UUID, plaintextToken string, ttl time.Duration, ip netip.Addr) (uuid.UUID, error) {
	hash := crypto.HMACToken(plaintextToken, s.pepper)
	var id uuid.UUID
	var ipArg any
	if ip.IsValid() {
		ipArg = ip.String()
	}
	err := q.QueryRow(ctx, `
		INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, ip_address)
		VALUES ($1, $2, now() + $3::INTERVAL, $4)
		RETURNING id
	`, userID, hash, ttl, ipArg).Scan(&id)
	return id, err
}

// GetByTokenForUpdate row-locks so concurrent confirm attempts can't race.
// Handler treats not-found / expired / already-used as INVALID_TOKEN.
func (s *TokenStore) GetByTokenForUpdate(ctx context.Context, q database.Querier, plaintextToken string) (*PasswordResetToken, error) {
	hash := crypto.HMACToken(plaintextToken, s.pepper)
	row := q.QueryRow(ctx, `
		SELECT id, user_id, expires_at, used_at, created_at
		FROM password_reset_tokens
		WHERE token_hash = $1
		FOR UPDATE
	`, hash)
	var t PasswordResetToken
	if err := row.Scan(&t.ID, &t.UserID, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrResetTokenNotFound
		}
		return nil, err
	}
	return &t, nil
}

// MarkUsed idempotent. Caller must hold the row under FOR UPDATE.
func (s *TokenStore) MarkUsed(ctx context.Context, q database.Querier, id uuid.UUID) error {
	_, err := q.Exec(ctx, `UPDATE password_reset_tokens SET used_at = now() WHERE id = $1`, id)
	return err
}

// GetByToken is the non-locking read for /validate. Must not hold a row
// lock across the request.
func (s *TokenStore) GetByToken(ctx context.Context, q database.Querier, plaintextToken string) (*PasswordResetToken, error) {
	hash := crypto.HMACToken(plaintextToken, s.pepper)
	row := q.QueryRow(ctx, `
		SELECT id, user_id, expires_at, used_at, created_at
		FROM password_reset_tokens
		WHERE token_hash = $1
	`, hash)
	var t PasswordResetToken
	if err := row.Scan(&t.ID, &t.UserID, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrResetTokenNotFound
		}
		return nil, err
	}
	return &t, nil
}

// InvalidateOutstandingForUser — OWASP Forgot Password: any new /request
// implicitly revokes any prior emailed link.
func (s *TokenStore) InvalidateOutstandingForUser(ctx context.Context, q database.Querier, userID uuid.UUID) (int64, error) {
	tag, err := q.Exec(ctx, `
		UPDATE password_reset_tokens
		SET used_at = now()
		WHERE user_id = $1
		  AND used_at IS NULL
		  AND expires_at > now()
	`, userID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
