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
