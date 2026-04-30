// Package settings owns the PATCH /api/settings/* handlers and the request
// types + validators for each settings domain (General, Security, Tokens,
// Email). Pointer fields allow PATCH callers to omit unchanged fields.
package settings

import (
	"net/mail"
	"strings"

	"github.com/abdo75/Schlass/internal/apierrors"
)

type GeneralSettings struct {
	InstanceName string `json:"instance_name"`
}

type SecuritySettings struct {
	MFARequired          *bool `json:"mfa_required"`
	PasswordMinLength    *int  `json:"password_min_length"`
	PasswordRequireUpper *bool `json:"password_require_upper"`
	PasswordRequireDigit *bool `json:"password_require_digit"`
	LockoutThreshold     *int  `json:"lockout_threshold"`
	LockoutDurationSecs  *int  `json:"lockout_duration_secs"`
}

type TokenSettings struct {
	AccessTokenTTLSecs  *int `json:"access_token_ttl_secs"`
	RefreshTokenTTLSecs *int `json:"refresh_token_ttl_secs"`
}

type AuditLogSettings struct {
	ViewLoggingEnabled *bool   `json:"audit_view_logging_enabled"`
	ExportMaxRows      *int    `json:"audit_export_max_rows"`
	// REQ-AUD-031 (M2): controls IP coarsening at emit time. One of
	// "coarse" (default), "country", "off". Read once at boot; updates
	// via this PATCH require a process restart to take effect.
	ClientIPMode *string `json:"audit_client_ip_mode,omitempty"`
}

type EmailSettings struct {
	SMTPHost     *string `json:"smtp_host"`
	SMTPPort     *int    `json:"smtp_port"`
	SMTPUsername *string `json:"smtp_username"`
	// SMTPPassword: empty string => keep current; non-empty => replace.
	SMTPPassword *string `json:"smtp_password"`
	SMTPFrom     *string `json:"smtp_from"`
}

func ValidateGeneralSettings(s *GeneralSettings) error {
	name := strings.TrimSpace(s.InstanceName)
	if name == "" {
		return &apierrors.ValidationError{Field: "instance_name", Code: "INSTANCE_NAME_REQUIRED"}
	}
	if len(name) > 64 {
		return &apierrors.ValidationError{Field: "instance_name", Code: "INSTANCE_NAME_TOO_LONG"}
	}
	if strings.ContainsAny(name, "\r\n\x00") {
		return &apierrors.ValidationError{Field: "instance_name", Code: "INSTANCE_NAME_INVALID"}
	}
	return nil
}

func ValidateSecuritySettings(s *SecuritySettings) error {
	if s.PasswordMinLength != nil {
		v := *s.PasswordMinLength
		if v < 8 || v > 128 {
			return &apierrors.ValidationError{Field: "password_min_length", Code: "PASSWORD_MIN_LENGTH_OUT_OF_RANGE"}
		}
	}
	if s.LockoutThreshold != nil {
		v := *s.LockoutThreshold
		if v < 1 || v > 50 {
			return &apierrors.ValidationError{Field: "lockout_threshold", Code: "LOCKOUT_THRESHOLD_OUT_OF_RANGE"}
		}
	}
	if s.LockoutDurationSecs != nil {
		v := *s.LockoutDurationSecs
		if v < 60 || v > 86400 {
			return &apierrors.ValidationError{Field: "lockout_duration_secs", Code: "LOCKOUT_DURATION_OUT_OF_RANGE"}
		}
	}
	return nil
}

func ValidateTokenSettings(s *TokenSettings) error {
	if s.AccessTokenTTLSecs != nil {
		v := *s.AccessTokenTTLSecs
		if v < 300 || v > 3600 {
			return &apierrors.ValidationError{Field: "access_token_ttl_secs", Code: "ACCESS_TOKEN_TTL_OUT_OF_RANGE"}
		}
	}
	if s.RefreshTokenTTLSecs != nil {
		v := *s.RefreshTokenTTLSecs
		if v < 3600 || v > 604800 {
			return &apierrors.ValidationError{Field: "refresh_token_ttl_secs", Code: "REFRESH_TOKEN_TTL_OUT_OF_RANGE"}
		}
	}
	return nil
}

func ValidateAuditLogSettings(s *AuditLogSettings) error {
	if s.ExportMaxRows != nil {
		if err := AuditExportMaxRows(*s.ExportMaxRows); err != nil {
			return err
		}
	}
	if s.ClientIPMode != nil {
		if err := AuditClientIPMode(*s.ClientIPMode); err != nil {
			return err
		}
	}
	return nil
}

// AuditClientIPMode validates the audit.client_ip_mode value against
// the REQ-AUD-031 enum. Anything outside the enum returns a validation
// error so a typo doesn't silently disable coarsening on the next boot.
func AuditClientIPMode(v string) error {
	switch v {
	case "coarse", "country", "off":
		return nil
	default:
		return &apierrors.ValidationError{Field: "audit_client_ip_mode", Code: "AUDIT_CLIENT_IP_MODE_INVALID"}
	}
}

// AuditExportMaxRows accepts 0 (uncapped) or any positive integer up to 1,000,000.
func AuditExportMaxRows(v int) error {
	if v < 0 {
		return &apierrors.ValidationError{Field: "audit_export_max_rows", Code: "AUDIT_EXPORT_MAX_ROWS_NEGATIVE"}
	}
	if v > 1_000_000 {
		return &apierrors.ValidationError{Field: "audit_export_max_rows", Code: "AUDIT_EXPORT_MAX_ROWS_TOO_LARGE"}
	}
	return nil
}

func ValidateEmailSettings(s *EmailSettings) error {
	if s.SMTPHost != nil {
		h := strings.TrimSpace(*s.SMTPHost)
		if h == "" {
			return &apierrors.ValidationError{Field: "smtp_host", Code: "SMTP_HOST_REQUIRED"}
		}
		if len(h) > 253 {
			return &apierrors.ValidationError{Field: "smtp_host", Code: "SMTP_HOST_TOO_LONG"}
		}
	}
	if s.SMTPPort != nil {
		v := *s.SMTPPort
		if v < 1 || v > 65535 {
			return &apierrors.ValidationError{Field: "smtp_port", Code: "SMTP_PORT_OUT_OF_RANGE"}
		}
	}
	if s.SMTPUsername != nil && len(*s.SMTPUsername) > 320 {
		return &apierrors.ValidationError{Field: "smtp_username", Code: "SMTP_USERNAME_TOO_LONG"}
	}
	if s.SMTPFrom != nil {
		addr := strings.TrimSpace(*s.SMTPFrom)
		if addr == "" {
			return &apierrors.ValidationError{Field: "smtp_from", Code: "SMTP_FROM_REQUIRED"}
		}
		if strings.ContainsAny(addr, "\r\n\x00") {
			return &apierrors.ValidationError{Field: "smtp_from", Code: "SMTP_FROM_INVALID"}
		}
		parsed, err := mail.ParseAddress(addr)
		if err != nil {
			return &apierrors.ValidationError{Field: "smtp_from", Code: "SMTP_FROM_INVALID"}
		}
		if strings.ContainsAny(parsed.Name, "\r\n\x00") {
			return &apierrors.ValidationError{Field: "smtp_from", Code: "SMTP_FROM_INVALID"}
		}
	}
	return nil
}
