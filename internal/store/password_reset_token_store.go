package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

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

type PasswordResetTokenStore struct{}

func NewPasswordResetTokenStore() *PasswordResetTokenStore { return &PasswordResetTokenStore{} }

// Insert stores the SHA-256 hash of the plaintext token. Plaintext never
// touches the DB. Returns the new token_id so callers can embed it in
// audit metadata.
func (s *PasswordResetTokenStore) Insert(ctx context.Context, q database.Querier, userID uuid.UUID, plaintextToken string, ttl time.Duration, ip netip.Addr) (uuid.UUID, error) {
	hash := sha256.Sum256([]byte(plaintextToken))
	var id uuid.UUID
	var ipArg any
	if ip.IsValid() {
		ipArg = ip.String()
	}
	err := q.QueryRow(ctx, `
		INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, ip_address)
		VALUES ($1, $2, now() + $3::INTERVAL, $4)
		RETURNING id
	`, userID, hash[:], ttl, ipArg).Scan(&id)
	return id, err
}

// GetByTokenForUpdate locks the row by SHA-256(token) so concurrent
// confirm attempts can't race. Returns ErrResetTokenNotFound on no
// match. Handler should treat not-found / expired / already-used as the
// same INVALID_TOKEN client-facing error.
func (s *PasswordResetTokenStore) GetByTokenForUpdate(ctx context.Context, q database.Querier, plaintextToken string) (*PasswordResetToken, error) {
	hash := sha256.Sum256([]byte(plaintextToken))
	row := q.QueryRow(ctx, `
		SELECT id, user_id, expires_at, used_at, created_at
		FROM password_reset_tokens
		WHERE token_hash = $1
		FOR UPDATE
	`, hash[:])
	var t PasswordResetToken
	if err := row.Scan(&t.ID, &t.UserID, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrResetTokenNotFound
		}
		return nil, err
	}
	return &t, nil
}

// MarkUsed flips used_at = now() on the row by id. Caller must hold the
// row under FOR UPDATE. Idempotent — marking used twice is a no-op.
func (s *PasswordResetTokenStore) MarkUsed(ctx context.Context, q database.Querier, id uuid.UUID) error {
	_, err := q.Exec(ctx, `UPDATE password_reset_tokens SET used_at = now() WHERE id = $1`, id)
	return err
}

// InvalidateOutstandingForUser marks every non-expired, unused reset
// token for the given user as used (used_at = now()). Returns the
// number of rows affected. Called by PostRequest before minting a
// fresh token so a new reset request implicitly revokes any prior
// emailed link (OWASP Forgot Password — "Invalidate any previously
// issued password reset tokens when a new one is generated").
func (s *PasswordResetTokenStore) InvalidateOutstandingForUser(ctx context.Context, q database.Querier, userID uuid.UUID) (int64, error) {
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
