package settings_test

import (
	"errors"
	"testing"

	"github.com/abdo75/Schlass/internal/apierrors"
	"github.com/abdo75/Schlass/internal/settings"
)

func TestValidateGeneralSettings(t *testing.T) {
	cases := []struct {
		name      string
		in        settings.GeneralSettings
		wantField string
	}{
		{"empty name", settings.GeneralSettings{InstanceName: ""}, "instance_name"},
		{"too long", settings.GeneralSettings{InstanceName: string(make([]byte, 65))}, "instance_name"},
		{"ok", settings.GeneralSettings{InstanceName: "Acme"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := settings.ValidateGeneralSettings(&c.in)
			if c.wantField == "" {
				if err != nil {
					t.Fatalf("want ok, got %v", err)
				}
				return
			}
			var ve *apierrors.ValidationError
			if !errors.As(err, &ve) || ve.Field != c.wantField {
				t.Fatalf("want field %q, got %v", c.wantField, err)
			}
		})
	}
}

func TestValidateSecuritySettings(t *testing.T) {
	minLen := 14
	upper := true
	digit := true
	mfa := true
	thresh := 5
	dur := 900
	ok := settings.SecuritySettings{MFARequired: &mfa, PasswordMinLength: &minLen, PasswordRequireUpper: &upper, PasswordRequireDigit: &digit, LockoutThreshold: &thresh, LockoutDurationSecs: &dur}
	if err := settings.ValidateSecuritySettings(&ok); err != nil {
		t.Fatalf("want ok, got %v", err)
	}

	tooShort := 4
	if err := settings.ValidateSecuritySettings(&settings.SecuritySettings{PasswordMinLength: &tooShort}); err == nil {
		t.Fatal("want error for short min length")
	}
	tooLong := 200
	if err := settings.ValidateSecuritySettings(&settings.SecuritySettings{PasswordMinLength: &tooLong}); err == nil {
		t.Fatal("want error for too-long min length")
	}
	badThresh := 0
	if err := settings.ValidateSecuritySettings(&settings.SecuritySettings{LockoutThreshold: &badThresh}); err == nil {
		t.Fatal("want error for zero threshold")
	}
	badDur := 10
	if err := settings.ValidateSecuritySettings(&settings.SecuritySettings{LockoutDurationSecs: &badDur}); err == nil {
		t.Fatal("want error for sub-60 duration")
	}
}

func TestValidateTokenSettings(t *testing.T) {
	at := 900
	rt := 86400
	if err := settings.ValidateTokenSettings(&settings.TokenSettings{AccessTokenTTLSecs: &at, RefreshTokenTTLSecs: &rt}); err != nil {
		t.Fatalf("want ok, got %v", err)
	}
	tooShortAT := 60
	if err := settings.ValidateTokenSettings(&settings.TokenSettings{AccessTokenTTLSecs: &tooShortAT}); err == nil {
		t.Fatal("want error for 60s AT")
	}
	tooLongRT := 700000
	if err := settings.ValidateTokenSettings(&settings.TokenSettings{RefreshTokenTTLSecs: &tooLongRT}); err == nil {
		t.Fatal("want error for >7d refresh")
	}
}

func TestValidateEmailSettings(t *testing.T) {
	host := "smtp.mailgun.org"
	port := 587
	user := "postmaster"
	pw := "somepassword"
	from := "no-reply@example.com"
	if err := settings.ValidateEmailSettings(&settings.EmailSettings{SMTPHost: &host, SMTPPort: &port, SMTPUsername: &user, SMTPPassword: &pw, SMTPFrom: &from}); err != nil {
		t.Fatalf("want ok, got %v", err)
	}
	badPort := 70000
	if err := settings.ValidateEmailSettings(&settings.EmailSettings{SMTPPort: &badPort}); err == nil {
		t.Fatal("want error for out-of-range port")
	}
	badFrom := "not-an-email"
	if err := settings.ValidateEmailSettings(&settings.EmailSettings{SMTPFrom: &badFrom}); err == nil {
		t.Fatal("want error for malformed from")
	}
}
