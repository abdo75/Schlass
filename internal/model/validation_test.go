package model_test

import (
	"testing"

	"github.com/schlass/schlass/internal/model"
)

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"valid", "admin@example.com", false},
		{"valid with subdomain", "user@mail.example.com", false},
		{"valid with plus", "user+tag@example.com", false},
		{"empty", "", true},
		{"no at sign", "admin-example.com", true},
		{"no domain", "admin@", true},
		{"no local part", "@example.com", true},
		{"too long", string(make([]byte, 250)) + "@a.co", true},
		{"spaces", "admin @example.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := model.ValidateEmail(tt.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEmail(%q) error = %v, wantErr %v", tt.email, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	policy := model.PasswordPolicy{
		MinLength:    12,
		RequireUpper: true,
		RequireDigit: true,
	}

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"valid", "SecurePass123", false},
		{"valid complex", "MyP@ssw0rd!!", false},
		{"too short", "Short1A", true},
		{"no uppercase", "alllowercase1", true},
		{"no digit", "AllLettersNoDigit", true},
		{"empty", "", true},
		{"exactly min length", "Abcdefghij1!", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := model.ValidatePassword(tt.password, policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePassword(%q) error = %v, wantErr %v", tt.password, err, tt.wantErr)
			}
		})
	}
}

func TestSetupRequestValidate(t *testing.T) {
	policy := model.PasswordPolicy{MinLength: 12, RequireUpper: true, RequireDigit: true}

	tests := []struct {
		name    string
		req     model.SetupRequest
		wantErr bool
	}{
		{
			"valid",
			model.SetupRequest{Email: "a@b.com", Password: "SecurePass123", ConfirmPassword: "SecurePass123", InstanceName: "My Company"},
			false,
		},
		{
			"passwords don't match",
			model.SetupRequest{Email: "a@b.com", Password: "SecurePass123", ConfirmPassword: "Different123", InstanceName: "X"},
			true,
		},
		{
			"missing instance name",
			model.SetupRequest{Email: "a@b.com", Password: "SecurePass123", ConfirmPassword: "SecurePass123", InstanceName: ""},
			true,
		},
		{
			"instance name too long",
			model.SetupRequest{Email: "a@b.com", Password: "SecurePass123", ConfirmPassword: "SecurePass123", InstanceName: string(make([]byte, 129))},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate(policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
