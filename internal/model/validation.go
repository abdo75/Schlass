package model

import (
	"fmt"
	"net/mail"
	"strings"
	"unicode"
)

type PasswordPolicy struct {
	MinLength    int
	RequireUpper bool
	RequireDigit bool
}

type SetupRequest struct {
	Email           string `json:"email"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
	InstanceName    string `json:"instance_name"`
}

func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email is required")
	}
	if len(email) > 254 {
		return fmt.Errorf("email must not exceed 254 characters")
	}
	if strings.ContainsAny(email, " \t\n\r") {
		return fmt.Errorf("email must not contain whitespace")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return fmt.Errorf("invalid email address")
	}
	return nil
}

func ValidatePassword(password string, policy PasswordPolicy) error {
	if len(password) < policy.MinLength {
		return fmt.Errorf("password must be at least %d characters", policy.MinLength)
	}

	if policy.RequireUpper {
		hasUpper := false
		for _, r := range password {
			if unicode.IsUpper(r) {
				hasUpper = true
				break
			}
		}
		if !hasUpper {
			return fmt.Errorf("password must contain at least one uppercase letter")
		}
	}

	if policy.RequireDigit {
		hasDigit := false
		for _, r := range password {
			if unicode.IsDigit(r) {
				hasDigit = true
				break
			}
		}
		if !hasDigit {
			return fmt.Errorf("password must contain at least one digit")
		}
	}

	return nil
}

func (r SetupRequest) Validate(policy PasswordPolicy) error {
	if err := ValidateEmail(r.Email); err != nil {
		return err
	}
	if err := ValidatePassword(r.Password, policy); err != nil {
		return err
	}
	if r.Password != r.ConfirmPassword {
		return fmt.Errorf("passwords do not match")
	}
	if r.InstanceName == "" {
		return fmt.Errorf("instance name is required")
	}
	if len(r.InstanceName) > 128 {
		return fmt.Errorf("instance name must not exceed 128 characters")
	}
	return nil
}
