package validate

import (
	"net/mail"
	"strings"

	"github.com/abdo75/Schlass/internal/apierrors"
)

// Email validates the format and length of an email address.
func Email(email string) error {
	if email == "" {
		return &apierrors.ValidationError{Message: "email is required"}
	}
	if len(email) > 254 {
		return &apierrors.ValidationError{Message: "email must not exceed 254 characters"}
	}
	if strings.ContainsAny(email, " \t\n\r") {
		return &apierrors.ValidationError{Message: "email must not contain whitespace"}
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return &apierrors.ValidationError{Message: "invalid email address"}
	}
	return nil
}
