package config

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// setRequiredEnv sets dummy values for every env var Load() requires so
// that tests focused on a single field can call Load() without error.
func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SCHLASS_DATABASE_URL", "postgres://user:pass@localhost:5432/db?sslmode=disable")
	t.Setenv("SCHLASS_MIGRATIONS_DATABASE_URL", "postgres://user:pass@localhost:5432/db?sslmode=disable")
	t.Setenv("SCHLASS_VALKEY_URL", "localhost:6379")
	t.Setenv("SCHLASS_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, 32)))
}

func TestLoad_RejectsPublicURLWithoutScheme(t *testing.T) {
	for _, v := range []string{"example.com", "//example.com", "ftp://example.com", "http://"} {
		t.Run(v, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv("SCHLASS_PUBLIC_URL", v)
			if _, err := Load(); err == nil {
				t.Fatalf("Load() with SCHLASS_PUBLIC_URL=%q should fail", v)
			}
		})
	}
}

func TestLoad_AcceptsValidPublicURL(t *testing.T) {
	for _, v := range []string{"http://localhost:3000", "https://auth.example.com", "https://auth.example.com:8443"} {
		t.Run(v, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv("SCHLASS_PUBLIC_URL", v)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() rejected valid URL %q: %v", v, err)
			}
			if cfg.SchlassPublicURL != v {
				t.Fatalf("SchlassPublicURL = %q, want %q", cfg.SchlassPublicURL, v)
			}
		})
	}
}

func TestLoad_SchlassPublicURL(t *testing.T) {
	setRequiredEnv(t)

	// Unset to verify the default.
	t.Setenv("SCHLASS_PUBLIC_URL", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SchlassPublicURL != "http://localhost:3000" {
		t.Fatalf("default: got %q, want %q", cfg.SchlassPublicURL, "http://localhost:3000")
	}

	// Now set an override and verify it wins.
	t.Setenv("SCHLASS_PUBLIC_URL", "https://idp.example.com")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SchlassPublicURL != "https://idp.example.com" {
		t.Fatalf("override: got %q, want %q", cfg.SchlassPublicURL, "https://idp.example.com")
	}
}

func TestLoad_HIBPDefaultsToEnabled(t *testing.T) {
	setRequiredEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.HIBPEnabled {
		t.Fatal("HIBPEnabled must default to true")
	}
	if cfg.HIBPEndpoint != "" {
		t.Fatalf("HIBPEndpoint default = %q, want empty (use hibp.DefaultHIBPEndpoint)", cfg.HIBPEndpoint)
	}
}

func TestLoad_HIBPEnabled_AcceptsBooleanLike(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"true", true}, {"false", false}, {"1", true}, {"0", false},
		{"on", true}, {"off", false}, {"yes", true}, {"no", false},
		{"TRUE", true}, {"False", false},
	} {
		t.Run(c.in, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv("SCHLASS_HIBP_ENABLED", c.in)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.HIBPEnabled != c.want {
				t.Fatalf("HIBPEnabled = %v, want %v", cfg.HIBPEnabled, c.want)
			}
		})
	}
}

func TestLoad_HIBPEnabled_RejectsGarbage(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SCHLASS_HIBP_ENABLED", "maybe")
	if _, err := Load(); err == nil {
		t.Fatal("expected rejection of non-boolean value")
	}
}

func TestLoad_HIBPEndpointAndTimeout(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SCHLASS_HIBP_ENDPOINT", "http://stub.test/range")
	t.Setenv("SCHLASS_HIBP_TIMEOUT_MS", "500")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HIBPEndpoint != "http://stub.test/range" {
		t.Fatalf("HIBPEndpoint = %q", cfg.HIBPEndpoint)
	}
	if cfg.HIBPTimeoutMS != 500 {
		t.Fatalf("HIBPTimeoutMS = %d", cfg.HIBPTimeoutMS)
	}
}

func TestLoad_HIBPTimeout_RejectsNegative(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SCHLASS_HIBP_TIMEOUT_MS", "-1")
	if _, err := Load(); err == nil {
		t.Fatal("expected rejection of negative timeout")
	}
}
