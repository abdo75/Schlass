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

// SetInt / SetBool / SetString are thin wrappers around the store for the
// settings PATCH handlers. They keep the handler free of instance_config
// key-encoding details.
func (s *ConfigService) SetInt(ctx context.Context, q database.Querier, key string, value int) error {
	return s.store.Set(ctx, q, key, value)
}

func (s *ConfigService) SetBool(ctx context.Context, q database.Querier, key string, value bool) error {
	return s.store.Set(ctx, q, key, value)
}

func (s *ConfigService) SetString(ctx context.Context, q database.Querier, key, value string) error {
	return s.store.Set(ctx, q, key, value)
}

// SettingsSnapshot is the full GET /api/settings response shape. Four
// domains with read-only (public) fields. SMTP password value never
// included; SMTPPasswordSet exposes whether a value exists.
type SettingsSnapshot struct {
	General  GeneralSnapshot  `json:"general"`
	Security SecuritySnapshot `json:"security"`
	Tokens   TokenSnapshot    `json:"tokens"`
	Email    EmailSnapshot    `json:"email"`
}

type GeneralSnapshot struct {
	InstanceName string `json:"instance_name"`
}

type SecuritySnapshot struct {
	MFARequired          bool `json:"mfa_required"`
	PasswordMinLength    int  `json:"password_min_length"`
	PasswordRequireUpper bool `json:"password_require_upper"`
	PasswordRequireDigit bool `json:"password_require_digit"`
	LockoutThreshold     int  `json:"lockout_threshold"`
	LockoutDurationSecs  int  `json:"lockout_duration_secs"`
}

type TokenSnapshot struct {
	AccessTokenTTLSecs  int `json:"access_token_ttl_secs"`
	RefreshTokenTTLSecs int `json:"refresh_token_ttl_secs"`
}

type EmailSnapshot struct {
	SMTPHost        string `json:"smtp_host"`
	SMTPPort        int    `json:"smtp_port"`
	SMTPUsername    string `json:"smtp_username"`
	SMTPPasswordSet bool   `json:"smtp_password_set"`
	SMTPFrom        string `json:"smtp_from"`
}

// GetSettingsSnapshot reads every settings-related instance_config key in
// one pass. Used by GET /api/settings + by internal/mail to load SMTP
// config without each caller doing per-key reads. Individual per-key
// errors are swallowed (missing rows default to zero values) mirroring
// the behaviour of GetInstanceName — setup guarantees every key is
// seeded, so a missing row indicates a regression caught elsewhere.
func (s *ConfigService) GetSettingsSnapshot(ctx context.Context, q database.Querier) (*SettingsSnapshot, error) {
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

	return &SettingsSnapshot{
		General: GeneralSnapshot{InstanceName: name},
		Security: SecuritySnapshot{
			MFARequired:          mfaReq,
			PasswordMinLength:    pwMin,
			PasswordRequireUpper: pwUpper,
			PasswordRequireDigit: pwDigit,
			LockoutThreshold:     lockT,
			LockoutDurationSecs:  lockD,
		},
		Tokens: TokenSnapshot{
			AccessTokenTTLSecs:  atTTL,
			RefreshTokenTTLSecs: rtTTL,
		},
		Email: EmailSnapshot{
			SMTPHost:        host,
			SMTPPort:        port,
			SMTPUsername:    user,
			SMTPFrom:        from,
			SMTPPasswordSet: !pwNull,
		},
	}, nil
}

// readNullableString swallows IsNull errors + returns "" for null values,
// matching the behaviour of GetInstanceName.
func readNullableString(ctx context.Context, st *store.ConfigStore, q database.Querier, key string) string {
	isNull, _ := st.IsNull(ctx, q, key)
	if isNull {
		return ""
	}
	v, _ := st.GetString(ctx, q, key)
	return v
}
