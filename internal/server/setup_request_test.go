package server_test

import (
	"testing"

	"github.com/abdo75/Schlass/internal/server"
	"github.com/abdo75/Schlass/internal/validate"
)

func TestSetupRequestValidate(t *testing.T) {
	policy := validate.PasswordPolicy{MinLength: 12, RequireUpper: true, RequireDigit: true}

	tests := []struct {
		name    string
		req     server.Request
		wantErr bool
	}{
		{
			"valid",
			server.Request{Email: "a@b.com", Password: "SecurePass123", ConfirmPassword: "SecurePass123", InstanceName: "My Company"},
			false,
		},
		{
			"passwords don't match",
			server.Request{Email: "a@b.com", Password: "SecurePass123", ConfirmPassword: "Different123", InstanceName: "X"},
			true,
		},
		{
			"missing instance name",
			server.Request{Email: "a@b.com", Password: "SecurePass123", ConfirmPassword: "SecurePass123", InstanceName: ""},
			true,
		},
		{
			"instance name too long",
			server.Request{Email: "a@b.com", Password: "SecurePass123", ConfirmPassword: "SecurePass123", InstanceName: string(make([]byte, 129))},
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
