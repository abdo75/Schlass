package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/abdo75/Schlass/internal/database"
)

type RecoveryCode struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	CodeHash  []byte
	UsedAt    *time.Time
	CreatedAt time.Time
}

type RecoveryCodeStore struct{}

func NewRecoveryCodeStore() *RecoveryCodeStore {
	return &RecoveryCodeStore{}
}

func (s *RecoveryCodeStore) Insert(ctx context.Context, q database.Querier, userID uuid.UUID, hashes [][]byte) error {
	if len(hashes) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, h := range hashes {
		batch.Queue(
			`INSERT INTO totp_recovery_codes (user_id, code_hash) VALUES ($1, $2)`,
			userID, h,
		)
	}
	br := q.SendBatch(ctx, batch)
	defer func() {
		_ = br.Close()
	}()
	for i := 0; i < len(hashes); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("insert recovery code %d: %w", i, err)
		}
	}
	return nil
}

// ListUnused returns in created_at order — stable for integration tests.
func (s *RecoveryCodeStore) ListUnused(ctx context.Context, q database.Querier, userID uuid.UUID) ([]RecoveryCode, error) {
	rows, err := q.Query(ctx,
		`SELECT id, user_id, code_hash, used_at, created_at
		 FROM totp_recovery_codes
		 WHERE user_id = $1 AND used_at IS NULL
		 ORDER BY created_at`,
		userID)
	if err != nil {
		return nil, fmt.Errorf("list unused recovery codes: %w", err)
	}
	defer rows.Close()
	var out []RecoveryCode
	for rows.Next() {
		var r RecoveryCode
		if err := rows.Scan(&r.ID, &r.UserID, &r.CodeHash, &r.UsedAt, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan recovery code: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *RecoveryCodeStore) CountUnused(ctx context.Context, q database.Querier, userID uuid.UUID) (int, error) {
	var n int
	err := q.QueryRow(ctx,
		`SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = $1 AND used_at IS NULL`,
		userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count unused recovery codes: %w", err)
	}
	return n, nil
}

// MarkUsed errors if the code was already burned or doesn't exist.
func (s *RecoveryCodeStore) MarkUsed(ctx context.Context, q database.Querier, codeID uuid.UUID) error {
	ct, err := q.Exec(ctx,
		`UPDATE totp_recovery_codes SET used_at = now() WHERE id = $1 AND used_at IS NULL`,
		codeID)
	if err != nil {
		return fmt.Errorf("mark recovery code used: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return errors.New("recovery code already used or not found")
	}
	return nil
}

func (s *RecoveryCodeStore) DeleteAllForUser(ctx context.Context, q database.Querier, userID uuid.UUID) (int64, error) {
	ct, err := q.Exec(ctx,
		`DELETE FROM totp_recovery_codes WHERE user_id = $1`,
		userID)
	if err != nil {
		return 0, fmt.Errorf("delete recovery codes: %w", err)
	}
	return ct.RowsAffected(), nil
}
