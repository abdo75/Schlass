package settings_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/abdo75/Schlass/internal/apierrors"
	"github.com/abdo75/Schlass/internal/settings"
)

func TestValidateGeneralSettings_RejectsCRLF(t *testing.T) {
	cases := []string{
		"Acme\r\nBcc: attacker@x.com",
		"Acme\nBcc: attacker@x.com",
		"Acme\rBcc: attacker@x.com",
		"Acme\x00null",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			err := settings.ValidateGeneralSettings(&settings.GeneralSettings{InstanceName: name})
			if err == nil {
				t.Fatalf("expected rejection for %q", name)
			}
			var ve *apierrors.ValidationError
			if !errors.As(err, &ve) || ve.Code != "INSTANCE_NAME_INVALID" {
				t.Fatalf("want ValidationError code INSTANCE_NAME_INVALID, got %v", err)
			}
		})
	}
}

func TestValidateEmailSettings_RejectsCRLFInFrom(t *testing.T) {
	addr := "no-reply@example.com\r\nBcc: attacker@x.com"
	err := settings.ValidateEmailSettings(&settings.EmailSettings{SMTPFrom: &addr})
	if err == nil {
		t.Fatalf("expected rejection for CRLF in smtp_from")
	}
	if !strings.Contains(err.Error(), "SMTP_FROM_INVALID") &&
		!strings.Contains(err.Error(), "invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}
