package model

import (
	"net/mail"
	"strings"
)

// GeneralSettings / SecuritySettings / TokenSettings / EmailSettings use
// pointer fields so PATCH callers can express "this field is unchanged" by
// leaving it nil. Validators only check non-nil fields.

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
		return &ValidationError{Field: "instance_name", Code: "instance_name.required"}
	}
	if len(name) > 64 {
		return &ValidationError{Field: "instance_name", Code: "instance_name.too_long"}
	}
	return nil
}

func ValidateSecuritySettings(s *SecuritySettings) error {
	if s.PasswordMinLength != nil {
		v := *s.PasswordMinLength
		if v < 8 || v > 128 {
			return &ValidationError{Field: "password_min_length", Code: "password_min_length.out_of_range"}
		}
	}
	if s.LockoutThreshold != nil {
		v := *s.LockoutThreshold
		if v < 1 || v > 50 {
			return &ValidationError{Field: "lockout_threshold", Code: "lockout_threshold.out_of_range"}
		}
	}
	if s.LockoutDurationSecs != nil {
		v := *s.LockoutDurationSecs
		if v < 60 || v > 86400 {
			return &ValidationError{Field: "lockout_duration_secs", Code: "lockout_duration_secs.out_of_range"}
		}
	}
	return nil
}

func ValidateTokenSettings(s *TokenSettings) error {
	if s.AccessTokenTTLSecs != nil {
		v := *s.AccessTokenTTLSecs
		if v < 300 || v > 3600 {
			return &ValidationError{Field: "access_token_ttl_secs", Code: "access_token_ttl_secs.out_of_range"}
		}
	}
	if s.RefreshTokenTTLSecs != nil {
		v := *s.RefreshTokenTTLSecs
		if v < 3600 || v > 604800 {
			return &ValidationError{Field: "refresh_token_ttl_secs", Code: "refresh_token_ttl_secs.out_of_range"}
		}
	}
	return nil
}

func ValidateEmailSettings(s *EmailSettings) error {
	if s.SMTPHost != nil {
		h := strings.TrimSpace(*s.SMTPHost)
		if h == "" {
			return &ValidationError{Field: "smtp_host", Code: "smtp_host.required"}
		}
		if len(h) > 253 {
			return &ValidationError{Field: "smtp_host", Code: "smtp_host.too_long"}
		}
	}
	if s.SMTPPort != nil {
		v := *s.SMTPPort
		if v < 1 || v > 65535 {
			return &ValidationError{Field: "smtp_port", Code: "smtp_port.out_of_range"}
		}
	}
	if s.SMTPUsername != nil && len(*s.SMTPUsername) > 320 {
		return &ValidationError{Field: "smtp_username", Code: "smtp_username.too_long"}
	}
	if s.SMTPFrom != nil {
		addr := strings.TrimSpace(*s.SMTPFrom)
		if addr == "" {
			return &ValidationError{Field: "smtp_from", Code: "smtp_from.required"}
		}
		if _, err := mail.ParseAddress(addr); err != nil {
			return &ValidationError{Field: "smtp_from", Code: "smtp_from.invalid"}
		}
	}
	return nil
}
