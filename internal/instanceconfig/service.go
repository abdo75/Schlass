// Service wraps Store with typed helpers and AES-256-GCM encryption for
// sensitive config values (smtp_password, etc.). All methods read through
// the Store using the caller-supplied Querier.
package instanceconfig

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/database"
	"github.com/abdo75/Schlass/internal/validate"
)

type Service struct {
	store         *Store
	encryptionKey []byte
}

func NewService(configStore *Store, encryptionKey []byte) *Service {
	return &Service{
		store:         configStore,
		encryptionKey: encryptionKey,
	}
}

func (s *Service) IsSetupComplete(ctx context.Context, q database.Querier) (bool, error) {
	return s.store.GetBool(ctx, q, "setup_complete")
}

func (s *Service) SetSetupComplete(ctx context.Context, q database.Querier) error {
	return s.store.Set(ctx, q, "setup_complete", true)
}

func (s *Service) InstanceName(ctx context.Context, q database.Querier) (string, error) {
	isNull, err := s.store.IsNull(ctx, q, "instance_name")
	if err != nil {
		return "", err
	}
	if isNull {
		return "", nil
	}
	return s.store.GetString(ctx, q, "instance_name")
}

func (s *Service) SetInstanceName(ctx context.Context, q database.Querier, name string) error {
	return s.store.Set(ctx, q, "instance_name", name)
}

func (s *Service) PasswordPolicy(ctx context.Context, q database.Querier) (validate.PasswordPolicy, error) {
	minLength, err := s.store.GetInt(ctx, q, "password_min_length")
	if err != nil {
		return validate.PasswordPolicy{}, err
	}
	requireUpper, err := s.store.GetBool(ctx, q, "password_require_upper")
	if err != nil {
		return validate.PasswordPolicy{}, err
	}
	requireDigit, err := s.store.GetBool(ctx, q, "password_require_digit")
	if err != nil {
		return validate.PasswordPolicy{}, err
	}
	return validate.PasswordPolicy{
		MinLength:    minLength,
		RequireUpper: requireUpper,
		RequireDigit: requireDigit,
	}, nil
}

func (s *Service) AccessTokenTTLSecs(ctx context.Context, q database.Querier) (int, error) {
	return s.store.GetInt(ctx, q, "access_token_ttl_secs")
}

// AuditClientIPMode returns the configured value for
// `audit.client_ip_mode` (REQ-AUD-031, M2). The string is one of
// "coarse" (default), "country", or "off". Callers translate to the
// audit.IPMode enum via audit.ParseIPMode at boot time.
//
// A missing key (only possible if the M2 migration didn't seed it,
// e.g. tests pointing at a pre-M2 schema) or an explicit JSON null
// collapses to ("coarse", nil) — the documented fallback. Real DB-level
// failures (pool unreachable, schema drift, permission denied) are
// returned as ("coarse", err) so the boot path can log them: the
// caller still gets a usable default but the failure is visible.
func (s *Service) AuditClientIPMode(ctx context.Context, q database.Querier) (string, error) {
	isNull, err := s.store.IsNull(ctx, q, "audit.client_ip_mode")
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "coarse", nil
		}
		return "coarse", err
	}
	if isNull {
		return "coarse", nil
	}
	v, err := s.store.GetString(ctx, q, "audit.client_ip_mode")
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "coarse", nil
		}
		return "coarse", err
	}
	if v == "" {
		return "coarse", nil
	}
	return v, nil
}

func (s *Service) AuditAnchorBackend(ctx context.Context, q database.Querier) (string, error) {
	v, err := s.stringWithDefault(ctx, q, "audit.anchor.backend", "none")
	if err != nil {
		return "none", err
	}
	if v == "append_only_file" {
		return "appendfile", nil
	}
	switch v {
	case "none", "appendfile", "s3", "gcs":
		return v, nil
	default:
		return "none", fmt.Errorf("instance_config: invalid audit.anchor.backend %q", v)
	}
}

func (s *Service) AuditAnchorBucket(ctx context.Context, q database.Querier) (string, error) {
	return s.stringWithDefault(ctx, q, "audit.anchor.bucket", "")
}

func (s *Service) AuditAnchorPath(ctx context.Context, q database.Querier) (string, error) {
	return s.stringWithDefault(ctx, q, "audit.anchor.path", "")
}

func (s *Service) AuditAnchorEventsPerAnchor(ctx context.Context, q database.Querier) (int, error) {
	return s.intWithDefault(ctx, q, "audit.anchor.events_per_anchor", 10000)
}

func (s *Service) AuditAnchorIntervalSecs(ctx context.Context, q database.Querier) (int, error) {
	return s.intWithDefault(ctx, q, "audit.anchor.interval_secs", 3600)
}

func (s *Service) AuditRetentionSecurityHotDays(ctx context.Context, q database.Querier) (int, error) {
	return s.intWithDefault(ctx, q, "audit.retention.security_hot_days", 365)
}

func (s *Service) AuditRetentionSecurityColdYears(ctx context.Context, q database.Querier) (int, error) {
	return s.intWithDefault(ctx, q, "audit.retention.security_cold_years", 6)
}

func (s *Service) AuditRetentionOperationalDays(ctx context.Context, q database.Querier) (int, error) {
	return s.intWithDefault(ctx, q, "audit.retention.operational_days", 90)
}

// AuditStreamBackend returns the configured outbound streamer backend.
// One of "none" (default — streaming disabled), "syslog" (RFC 5424 over
// TCP+TLS), or "otlp" (OTLP HTTP/JSON). Unknown values return "none"
// with a fmt-wrapped error so the boot path can log + continue.
func (s *Service) AuditStreamBackend(ctx context.Context, q database.Querier) (string, error) {
	v, err := s.stringWithDefault(ctx, q, "audit.stream.backend", "none")
	if err != nil {
		return "none", err
	}
	switch v {
	case "none", "syslog", "otlp":
		return v, nil
	default:
		return "none", fmt.Errorf("instance_config: invalid audit.stream.backend %q", v)
	}
}

// AuditStreamEndpoint returns the SIEM endpoint URL. For syslog this is
// `host:port` (TLS is mandatory and assumed; see syslog streamer);
// for OTLP this is a full https:// URL terminating at the receiver.
func (s *Service) AuditStreamEndpoint(ctx context.Context, q database.Querier) (string, error) {
	return s.stringWithDefault(ctx, q, "audit.stream.endpoint", "")
}

// AuditStreamTokenRef returns the bearer token sent on OTLP requests
// when non-empty. Plain literal for now — secret-store resolution is
// out of scope for M8.
func (s *Service) AuditStreamTokenRef(ctx context.Context, q database.Querier) (string, error) {
	return s.stringWithDefault(ctx, q, "audit.stream.token_ref", "")
}

// AuditStreamPollSecs returns the watermark-poll worker tick interval
// in seconds. Floors at 1; defaults to 5.
func (s *Service) AuditStreamPollSecs(ctx context.Context, q database.Querier) (int, error) {
	return s.intWithDefault(ctx, q, "audit.stream.poll_secs", 5)
}

// AuditStreamFormat returns "raw" (default) or "caep". "raw" emits the
// stream.Event JSON payload; "caep" projects + signs RFC 8417 SETs and
// filters to events with a registered CAEP URN mapping.
func (s *Service) AuditStreamFormat(ctx context.Context, q database.Querier) (string, error) {
	v, err := s.stringWithDefault(ctx, q, "audit.stream.format", "raw")
	if err != nil {
		return "raw", err
	}
	switch v {
	case "raw", "caep":
		return v, nil
	default:
		return "raw", nil
	}
}

// AuditStreamBatchSize returns the maximum events per push. Floors at 1,
// caps at 1000 silently (a runaway value would balloon receiver memory);
// defaults to 100.
func (s *Service) AuditStreamBatchSize(ctx context.Context, q database.Querier) (int, error) {
	v, err := s.intWithDefault(ctx, q, "audit.stream.batch_size", 100)
	if err != nil {
		return 100, err
	}
	if v > 1000 {
		return 1000, nil
	}
	return v, nil
}

func (s *Service) AuditColdTierBackend(ctx context.Context, q database.Querier) (string, error) {
	v, err := s.stringWithDefault(ctx, q, "audit.cold_tier.backend", "same_as_anchor")
	if err != nil {
		return "same_as_anchor", err
	}
	switch v {
	case "same_as_anchor", "local", "none":
		return v, nil
	default:
		return "same_as_anchor", fmt.Errorf("instance_config: invalid audit.cold_tier.backend %q", v)
	}
}

func (s *Service) stringWithDefault(ctx context.Context, q database.Querier, key, def string) (string, error) {
	isNull, err := s.store.IsNull(ctx, q, key)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return def, nil
		}
		return def, err
	}
	if isNull {
		return def, nil
	}
	v, err := s.store.GetString(ctx, q, key)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return def, nil
		}
		return def, err
	}
	// An empty stored value is treated as unset when a non-empty default exists.
	// Operators wanting to explicitly disable a string-valued key must use the
	// sentinel value (e.g. "none"), not the empty string.
	if v == "" && def != "" {
		return def, nil
	}
	return v, nil
}

func (s *Service) intWithDefault(ctx context.Context, q database.Querier, key string, def int) (int, error) {
	isNull, err := s.store.IsNull(ctx, q, key)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return def, nil
		}
		return def, err
	}
	if isNull {
		return def, nil
	}
	v, err := s.store.GetInt(ctx, q, key)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return def, nil
		}
		return def, err
	}
	if v <= 0 {
		return def, nil
	}
	return v, nil
}

func (s *Service) RefreshTokenTTLSecs(ctx context.Context, q database.Querier) (int, error) {
	return s.store.GetInt(ctx, q, "refresh_token_ttl_secs")
}

func (s *Service) GetBool(ctx context.Context, q database.Querier, key string) (bool, error) {
	return s.store.GetBool(ctx, q, key)
}

func (s *Service) GetInt(ctx context.Context, q database.Querier, key string) (int, error) {
	return s.store.GetInt(ctx, q, key)
}

func (s *Service) Set(ctx context.Context, q database.Querier, key string, value any) error {
	return s.store.Set(ctx, q, key, value)
}

func (s *Service) EncryptedValue(ctx context.Context, q database.Querier, key string) (string, error) {
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

	plaintext, err := crypto.Decrypt(ciphertext, s.encryptionKey, encryptedValueAAD(key))
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func (s *Service) SetEncryptedValue(ctx context.Context, q database.Querier, key, plaintext string) error {
	ciphertext, err := crypto.Encrypt([]byte(plaintext), s.encryptionKey, encryptedValueAAD(key))
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	return s.store.Set(ctx, q, key, encoded)
}

func encryptedValueAAD(key string) []byte {
	return []byte("instance_config:" + key)
}

func (s *Service) SetInt(ctx context.Context, q database.Querier, key string, value int) error {
	return s.store.Set(ctx, q, key, value)
}

func (s *Service) SetBool(ctx context.Context, q database.Querier, key string, value bool) error {
	return s.store.Set(ctx, q, key, value)
}

func (s *Service) SetString(ctx context.Context, q database.Querier, key, value string) error {
	return s.store.Set(ctx, q, key, value)
}

func (s *Service) Settings(ctx context.Context, q database.Querier) (*Settings, error) {
	name, _ := s.InstanceName(ctx, q)

	mfaReq, _ := s.store.GetBool(ctx, q, "mfa_required")
	pwMin, _ := s.store.GetInt(ctx, q, "password_min_length")
	pwUpper, _ := s.store.GetBool(ctx, q, "password_require_upper")
	pwDigit, _ := s.store.GetBool(ctx, q, "password_require_digit")
	lockT, _ := s.store.GetInt(ctx, q, "lockout_threshold")
	lockD, _ := s.store.GetInt(ctx, q, "lockout_duration_secs")
	atTTL, _ := s.store.GetInt(ctx, q, "access_token_ttl_secs")
	rtTTL, _ := s.store.GetInt(ctx, q, "refresh_token_ttl_secs")
	auditViewLoggingEnabled, _ := s.store.GetBool(ctx, q, "audit_view_logging_enabled")
	auditExportMaxRows, _ := s.store.GetInt(ctx, q, "audit_export_max_rows")
	auditClientIPMode, _ := s.AuditClientIPMode(ctx, q)

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
		AuditLog: AuditLogSettings{
			ViewLoggingEnabled: auditViewLoggingEnabled,
			ExportMaxRows:      auditExportMaxRows,
			ClientIPMode:       auditClientIPMode,
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

func readNullableString(ctx context.Context, st *Store, q database.Querier, key string) string {
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
	AuditLog AuditLogSettings `json:"audit_log"`
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

type AuditLogSettings struct {
	ViewLoggingEnabled bool   `json:"audit_view_logging_enabled"`
	ExportMaxRows      int    `json:"audit_export_max_rows"`
	ClientIPMode       string `json:"audit_client_ip_mode"`
}

type EmailSettings struct {
	SMTPHost        string `json:"smtp_host"`
	SMTPPort        int    `json:"smtp_port"`
	SMTPUsername    string `json:"smtp_username"`
	SMTPPasswordSet bool   `json:"smtp_password_set"`
	SMTPFrom        string `json:"smtp_from"`
}
