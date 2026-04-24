// Package server owns the first-boot wizard request type and its validation.
package server

import (
	"github.com/abdo75/Schlass/internal/apierrors"
	"github.com/abdo75/Schlass/internal/validate"
)

// Request carries the payload for POST /api/setup.
type Request struct {
	Email           string `json:"email"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
	InstanceName    string `json:"instance_name"`
}

func (r Request) Validate(policy validate.PasswordPolicy) error {
	if err := validate.Email(r.Email); err != nil {
		return err
	}
	if err := validate.Password(r.Password, policy); err != nil {
		return err
	}
	if r.Password != r.ConfirmPassword {
		return &apierrors.ValidationError{Message: "passwords do not match"}
	}
	if r.InstanceName == "" {
		return &apierrors.ValidationError{Message: "instance name is required"}
	}
	if len(r.InstanceName) > 128 {
		return &apierrors.ValidationError{Message: "instance name must not exceed 128 characters"}
	}
	return nil
}
