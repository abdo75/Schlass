// InstanceConfig represents the instance_config Postgres table
// Here are methods to handle the instance-level settings
package config

import (
	"context"
	"encoding/base64"

	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/database"
	"github.com/abdo75/Schlass/internal/model"
	"github.com/abdo75/Schlass/internal/store"
)

type InstanceConfig struct {
	store         *store.ConfigStore
	encryptionKey []byte
}

func NewInstanceConfig(configStore *store.ConfigStore, encryptionKey []byte) *InstanceConfig {
	return &InstanceConfig{
		store:         configStore,
		encryptionKey: encryptionKey,
	}
}

func (s *InstanceConfig) IsSetupComplete(ctx context.Context, q database.Querier) (bool, error) {
	return s.store.GetBool(ctx, q, "setup_complete")
}

func (s *InstanceConfig) SetSetupComplete(ctx context.Context, q database.Querier) error {
	return s.store.Set(ctx, q, "setup_complete", true)
}

func (s *InstanceConfig) GetInstanceName(ctx context.Context, q database.Querier) (string, error) {
	isNull, err := s.store.IsNull(ctx, q, "instance_name")
	if err != nil {
		return "", err
	}
	if isNull {
		return "", nil
	}
	return s.store.GetString(ctx, q, "instance_name")
}

func (s *InstanceConfig) SetInstanceName(ctx context.Context, q database.Querier, name string) error {
	return s.store.Set(ctx, q, "instance_name", name)
}

func (s *InstanceConfig) GetPasswordPolicy(ctx context.Context, q database.Querier) (model.PasswordPolicy, error) {
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

func (s *InstanceConfig) GetEncryptedValue(ctx context.Context, q database.Querier, key string) (string, error) {
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

func (s *InstanceConfig) SetEncryptedValue(ctx context.Context, q database.Querier, key, plaintext string) error {
	ciphertext, err := crypto.Encrypt([]byte(plaintext), s.encryptionKey)
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	return s.store.Set(ctx, q, key, encoded)
}

func (s *InstanceConfig) SetInt(ctx context.Context, q database.Querier, key string, value int) error {
	return s.store.Set(ctx, q, key, value)
}

func (s *InstanceConfig) SetBool(ctx context.Context, q database.Querier, key string, value bool) error {
	return s.store.Set(ctx, q, key, value)
}

func (s *InstanceConfig) SetString(ctx context.Context, q database.Querier, key, value string) error {
	return s.store.Set(ctx, q, key, value)
}

func (s *InstanceConfig) GetSettings(ctx context.Context, q database.Querier) (*Settings, error) {
	name, _ := s.GetInstanceName(ctx, q)

	mfaReq, _ := s.store.GetBool(ctx, q, "mfa_required")
	pwMin, _ := s.store.GetInt(ctx, q, "password_min_length")
	pwUpper, _ := s.store.GetBool(ctx, q, "password_require_upper")
	pwDigit, _ := s.store.GetBool(ctx, q, "password_require_digit")
	lockT, _ := s.store.GetInt(ctx, q, "lockout_threshold")
	lockD, _ := s.store.GetInt(ctx, q, "lockout_duration_secs")
	atTTL, _ := s.store.GetInt(ctx, q, "access_token_ttl_secs")
	rtTTL, _ := s.store.GetInt(ctx, q, "refresh_token_ttl_secs")

	host := readNullableString(ctx, s.store, q, "smtp_host")
	port, _ := s.store.GetInt(ctx, q, "smtp_port")
	user := readNullableString(ctx, s.store, q, "smtp_username")
	from := readNullableString(ctx, s.store, q, "smtp_from")
	pwNull, _ := s.store.IsNull(ctx, q, "smtp_password")

	return &Settings{
		General: GeneralSettings{InstanceName: name},
		Security: SecuritySettings{
			MFARequired:          mfaReq,
			PasswordMinLength:    pwMin,
			PasswordRequireUpper: pwUpper,
			PasswordRequireDigit: pwDigit,
			LockoutThreshold:     lockT,
			LockoutDurationSecs:  lockD,
		},
		Tokens: TokenSettings{
			AccessTokenTTLSecs:  atTTL,
			RefreshTokenTTLSecs: rtTTL,
		},
		Email: EmailSettings{
			SMTPHost:        host,
			SMTPPort:        port,
			SMTPUsername:    user,
			SMTPFrom:        from,
			SMTPPasswordSet: !pwNull,
		},
	}, nil
}

func readNullableString(ctx context.Context, st *store.ConfigStore, q database.Querier, key string) string {
	isNull, _ := st.IsNull(ctx, q, key)
	if isNull {
		return ""
	}
	v, _ := st.GetString(ctx, q, key)
	return v
}

type Settings struct {
	General  GeneralSettings  `json:"general"`
	Security SecuritySettings `json:"security"`
	Tokens   TokenSettings    `json:"tokens"`
	Email    EmailSettings    `json:"email"`
}

type GeneralSettings struct {
	InstanceName string `json:"instance_name"`
}

type SecuritySettings struct {
	MFARequired          bool `json:"mfa_required"`
	PasswordMinLength    int  `json:"password_min_length"`
	PasswordRequireUpper bool `json:"password_require_upper"`
	PasswordRequireDigit bool `json:"password_require_digit"`
	LockoutThreshold     int  `json:"lockout_threshold"`
	LockoutDurationSecs  int  `json:"lockout_duration_secs"`
}

type TokenSettings struct {
	AccessTokenTTLSecs  int `json:"access_token_ttl_secs"`
	RefreshTokenTTLSecs int `json:"refresh_token_ttl_secs"`
}

type EmailSettings struct {
	SMTPHost        string `json:"smtp_host"`
	SMTPPort        int    `json:"smtp_port"`
	SMTPUsername    string `json:"smtp_username"`
	SMTPPasswordSet bool   `json:"smtp_password_set"`
	SMTPFrom        string `json:"smtp_from"`
}
