package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/abdo75/Schlass/internal/database"
)

type ConfigStore struct{}

func NewConfigStore() *ConfigStore {
	return &ConfigStore{}
}

func (s *ConfigStore) Get(ctx context.Context, q database.Querier, key string) (json.RawMessage, error) {
	var value json.RawMessage
	err := q.QueryRow(ctx,
		"SELECT value FROM instance_config WHERE key = $1", key,
	).Scan(&value)
	if err != nil {
		return nil, fmt.Errorf("config get %q: %w", key, err)
	}
	return value, nil
}

func (s *ConfigStore) GetBool(ctx context.Context, q database.Querier, key string) (bool, error) {
	raw, err := s.Get(ctx, q, key)
	if err != nil {
		return false, err
	}
	var result bool
	if err := json.Unmarshal(raw, &result); err != nil {
		return false, fmt.Errorf("config %q is not a boolean: %w", key, err)
	}
	return result, nil
}

func (s *ConfigStore) GetInt(ctx context.Context, q database.Querier, key string) (int, error) {
	raw, err := s.Get(ctx, q, key)
	if err != nil {
		return 0, err
	}
	var result int
	if err := json.Unmarshal(raw, &result); err != nil {
		return 0, fmt.Errorf("config %q is not an integer: %w", key, err)
	}
	return result, nil
}

func (s *ConfigStore) GetString(ctx context.Context, q database.Querier, key string) (string, error) {
	raw, err := s.Get(ctx, q, key)
	if err != nil {
		return "", err
	}
	var result string
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("config %q is not a string: %w", key, err)
	}
	return result, nil
}

func (s *ConfigStore) IsNull(ctx context.Context, q database.Querier, key string) (bool, error) {
	raw, err := s.Get(ctx, q, key)
	if err != nil {
		return false, err
	}
	return string(raw) == "null", nil
}

func (s *ConfigStore) Set(ctx context.Context, q database.Querier, key string, value any) error {
	jsonValue, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("config set %q: failed to marshal value: %w", key, err)
	}
	_, err = q.Exec(ctx,
		"UPDATE instance_config SET value = $1, updated_at = $2 WHERE key = $3",
		jsonValue, time.Now(), key,
	)
	if err != nil {
		return fmt.Errorf("config set %q: %w", key, err)
	}
	return nil
}
