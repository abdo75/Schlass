package validate_test

import (
	"testing"

	"github.com/abdo75/Schlass/internal/validate"
)

func TestEmail(t *testing.T) {
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
			err := validate.Email(tt.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("Email(%q) error = %v, wantErr %v", tt.email, err, tt.wantErr)
			}
		})
	}
}

func TestPassword(t *testing.T) {
	policy := validate.PasswordPolicy{
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
			err := validate.Password(tt.password, policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("Password(%q) error = %v, wantErr %v", tt.password, err, tt.wantErr)
			}
		})
	}
}
