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
