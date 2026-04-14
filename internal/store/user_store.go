package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/schlass/schlass/internal/database"
)

type UserStore struct{}

func NewUserStore() *UserStore {
	return &UserStore{}
}

func (s *UserStore) Create(ctx context.Context, q database.Querier, email, passwordHash, role string, forcePasswordChange bool) (uuid.UUID, error) {
	var id uuid.UUID
	err := q.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, role, force_password_change)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id`,
		email, passwordHash, role, forcePasswordChange,
	).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("create user: %w", err)
	}
	return id, nil
}
