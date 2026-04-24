// Package signingkeys owns the signing_keys table: lifecycle management for
// RSA-2048 OIDC signing keys (active → retiring → retired). Caller owns the
// connection.
package signingkeys

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/abdo75/Schlass/internal/database"
)

type SigningKey struct {
	ID                  uuid.UUID
	Algorithm           string
	PublicKeyPEM        []byte
	PrivateKeyEncrypted []byte
	Status              string // active | retiring | retired
	CreatedAt           time.Time
	RotatedAt           *time.Time
}

type Store struct{}

func NewStore() *Store { return &Store{} }

func (s *Store) Insert(
	ctx context.Context, q database.Querier,
	publicPEM, privateEncrypted []byte, status string,
) (uuid.UUID, error) {
	var id uuid.UUID
	err := q.QueryRow(ctx, `
		INSERT INTO signing_keys (algorithm, public_key_pem, private_key_encrypted, status)
		VALUES ('RS256', $1, $2, $3)
		RETURNING id
	`, string(publicPEM), privateEncrypted, status).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("signing_key insert: %w", err)
	}
	return id, nil
}

// ListPublishable returns active + retiring (never retired), active first.
func (s *Store) ListPublishable(
	ctx context.Context, q database.Querier,
) ([]*SigningKey, error) {
	rows, err := q.Query(ctx, `
		SELECT id, algorithm, public_key_pem, private_key_encrypted,
		       status, created_at, rotated_at
		FROM signing_keys
		WHERE status IN ('active', 'retiring')
		ORDER BY CASE status WHEN 'active' THEN 0 ELSE 1 END, created_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("signing_key list: %w", err)
	}
	defer rows.Close()
	var keys []*SigningKey
	for rows.Next() {
		var k SigningKey
		var pubStr string
		if err := rows.Scan(&k.ID, &k.Algorithm, &pubStr, &k.PrivateKeyEncrypted,
			&k.Status, &k.CreatedAt, &k.RotatedAt); err != nil {
			return nil, err
		}
		k.PublicKeyPEM = []byte(pubStr)
		keys = append(keys, &k)
	}
	return keys, rows.Err()
}

func (s *Store) GetActive(
	ctx context.Context, q database.Querier,
) (*SigningKey, error) {
	var k SigningKey
	var pubStr string
	err := q.QueryRow(ctx, `
		SELECT id, algorithm, public_key_pem, private_key_encrypted,
		       status, created_at, rotated_at
		FROM signing_keys
		WHERE status = 'active'
		LIMIT 1
	`).Scan(&k.ID, &k.Algorithm, &pubStr, &k.PrivateKeyEncrypted,
		&k.Status, &k.CreatedAt, &k.RotatedAt)
	if err != nil {
		return nil, err
	}
	k.PublicKeyPEM = []byte(pubStr)
	return &k, nil
}

// MarkRetiring: active → retiring, stamps rotated_at=now().
func (s *Store) MarkRetiring(
	ctx context.Context, q database.Querier, id uuid.UUID,
) error {
	_, err := q.Exec(ctx, `
		UPDATE signing_keys
		SET status = 'retiring', rotated_at = now()
		WHERE id = $1 AND status = 'active'
	`, id)
	return err
}

// MarkRetired: retiring → retired.
func (s *Store) MarkRetired(
	ctx context.Context, q database.Querier, id uuid.UUID,
) error {
	_, err := q.Exec(ctx, `
		UPDATE signing_keys
		SET status = 'retired'
		WHERE id = $1 AND status = 'retiring'
	`, id)
	return err
}

// ListRetirable: retiring keys whose rotated_at is older than cutoff.
func (s *Store) ListRetirable(
	ctx context.Context, q database.Querier, cutoff time.Time,
) ([]uuid.UUID, error) {
	rows, err := q.Query(ctx, `
		SELECT id FROM signing_keys
		WHERE status = 'retiring' AND rotated_at < $1
	`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
