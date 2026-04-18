package config

import (
	"context"
	"encoding/base64"

	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/database"
	"github.com/abdo75/Schlass/internal/model"
	"github.com/abdo75/Schlass/internal/store"
)

type ConfigService struct {
	store         *store.ConfigStore
	encryptionKey []byte
}

func NewConfigService(configStore *store.ConfigStore, encryptionKey []byte) *ConfigService {
	return &ConfigService{
		store:         configStore,
		encryptionKey: encryptionKey,
	}
}

func (s *ConfigService) IsSetupComplete(ctx context.Context, q database.Querier) (bool, error) {
	return s.store.GetBool(ctx, q, "setup_complete")
}

func (s *ConfigService) SetSetupComplete(ctx context.Context, q database.Querier) error {
	return s.store.Set(ctx, q, "setup_complete", true)
}

func (s *ConfigService) SetInstanceName(ctx context.Context, q database.Querier, name string) error {
	return s.store.Set(ctx, q, "instance_name", name)
}

// GetInstanceName returns the human-readable instance name from instance_config.
// Returns "" on error or when the value is NULL/empty — callers should fall
// back to "Schlass".
func (s *ConfigService) GetInstanceName(ctx context.Context, q database.Querier) (string, error) {
	isNull, err := s.store.IsNull(ctx, q, "instance_name")
	if err != nil {
		return "", err
	}
	if isNull {
		return "", nil
	}
	return s.store.GetString(ctx, q, "instance_name")
}

func (s *ConfigService) GetPasswordPolicy(ctx context.Context, q database.Querier) (model.PasswordPolicy, error) {
	minLength, err := s.store.GetInt(ctx, q, "password_min_length")
	if err != nil {
		return model.PasswordPolicy{}, err
	}
	requireUpper, err := s.store.GetBool(ctx, q, "password_require_upper")
	if err != nil {
		return model.PasswordPolicy{}, err
	}
	requireDigit, err := s.store.GetBool(ctx, q, "password_require_digit")
	if err != nil {
		return model.PasswordPolicy{}, err
	}
	return model.PasswordPolicy{
		MinLength:    minLength,
		RequireUpper: requireUpper,
		RequireDigit: requireDigit,
	}, nil
}

func (s *ConfigService) SetEncryptedValue(ctx context.Context, q database.Querier, key, plaintext string) error {
	ciphertext, err := crypto.Encrypt([]byte(plaintext), s.encryptionKey)
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	return s.store.Set(ctx, q, key, encoded)
}

func (s *ConfigService) GetEncryptedValue(ctx context.Context, q database.Querier, key string) (string, error) {
	isNull, err := s.store.IsNull(ctx, q, key)
	if err != nil {
		return "", err
	}
	if isNull {
		return "", nil
	}

	encoded, err := s.store.GetString(ctx, q, key)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	plaintext, err := crypto.Decrypt(ciphertext, s.encryptionKey)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
