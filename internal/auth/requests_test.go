package auth

import (
	"errors"
	"strings"
	"testing"

	"github.com/abdo75/Schlass/internal/apierrors"
)

func TestLoginRequest_Validate(t *testing.T) {
	cases := []struct {
		name    string
		req     LoginRequest
		wantErr bool
	}{
		{"valid", LoginRequest{Email: "a@b.co", Password: "hunter2hunter2"}, false},
		{"empty email", LoginRequest{Email: "", Password: "hunter2hunter2"}, true},
		{"email too long", LoginRequest{Email: strings.Repeat("x", 321) + "@b.co", Password: "hunter2hunter2"}, true},
		{"empty password", LoginRequest{Email: "a@b.co", Password: ""}, true},
		{"password too long", LoginRequest{Email: "a@b.co", Password: strings.Repeat("x", 257)}, true},
		{"malformed email", LoginRequest{Email: "not-an-email", Password: "hunter2hunter2"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr {
				var verr *apierrors.ValidationError
				if !errors.As(err, &verr) {
					t.Fatalf("expected *apierrors.ValidationError, got %T: %v", err, err)
				}
			}
		})
	}
}
