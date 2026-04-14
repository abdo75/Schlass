package model

import (
	"strings"
)

const (
	maxEmailLen    = 320 // RFC 5321 local-part (64) + "@" + domain (255) + safety margin
	maxPasswordLen = 256 // CPU-DoS defense against Argon2id on arbitrarily long input
)

// LoginRequest is the decoded body of POST /api/login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Validate enforces the length and shape checks applied before any DB access.
//
// Email is deliberately NOT normalized here (no trim, no lowercase). The setup
// handler stores emails verbatim (see internal/handler/setup.go), so normalizing
// login would break authentication for users registered with mixed-case or
// whitespace-padded addresses. A future cross-cutting PR should add consistent
// normalization to both setup and login paths.
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
