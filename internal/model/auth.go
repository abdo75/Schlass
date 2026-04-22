package model

import (
	"strings"
)

const (
	maxEmailLen    = 320 // RFC 5321 local (64) + "@" + domain (255) + margin
	maxPasswordLen = 256 // CPU-DoS defense against Argon2id on long input
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`

	// ReturnTo threaded through login → MFA → force-password-change when it
	// validates via SanitizeReturnTo at the handler boundary. Absent = role-
	// based routing.
	ReturnTo string `json:"return_to,omitempty"`
}

// Email is NOT normalized here: setup handler stores emails verbatim, so
// trim/lowercase on login would break auth for users registered with mixed
// case. Normalization is applied at the handler boundary instead.
func (r *LoginRequest) Validate() error {
	if r.Email == "" {
		return &ValidationError{Message: "email is required"}
	}
	if len(r.Email) > maxEmailLen {
		return &ValidationError{Message: "email is too long"}
	}
	if !strings.Contains(r.Email, "@") {
		return &ValidationError{Message: "email is malformed"}
	}
	if r.Password == "" {
		return &ValidationError{Message: "password is required"}
	}
	if len(r.Password) > maxPasswordLen {
		return &ValidationError{Message: "password is too long"}
	}
	return nil
}
