package validate

import (
	"fmt"
	"unicode"

	"github.com/abdo75/Schlass/internal/apierrors"
)

// PasswordPolicy defines the constraints applied when validating a password.
type PasswordPolicy struct {
	MinLength    int
	RequireUpper bool
	RequireDigit bool
}

// Password validates a password against the given policy.
func Password(p string, policy PasswordPolicy) error {
	if len(p) < policy.MinLength {
		return &apierrors.PasswordPolicyError{Message: fmt.Sprintf("password must be at least %d characters", policy.MinLength)}
	}

	if policy.RequireUpper {
		hasUpper := false
		for _, r := range p {
			if unicode.IsUpper(r) {
				hasUpper = true
				break
			}
		}
		if !hasUpper {
			return &apierrors.PasswordPolicyError{Message: "password must contain at least one uppercase letter"}
		}
	}

	if policy.RequireDigit {
		hasDigit := false
		for _, r := range p {
			if unicode.IsDigit(r) {
				hasDigit = true
				break
			}
		}
		if !hasDigit {
			return &apierrors.PasswordPolicyError{Message: "password must contain at least one digit"}
		}
	}

	return nil
}
