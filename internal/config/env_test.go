package config

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

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

func TestLoad_PublicURLDefault(t *testing.T) {
	setRequiredEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SchlassPublicURL != "http://localhost:3000" {
		t.Fatalf("default: got %q, want %q", cfg.SchlassPublicURL, "http://localhost:3000")
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
	if cfg.HIBPEndpoint != "https://api.pwnedpasswords.com/range" {
		t.Fatalf("HIBPEndpoint default = %q, want canonical HIBP range API URL", cfg.HIBPEndpoint)
	}
	if cfg.HIBPTimeoutMS != 1500 {
		t.Fatalf("HIBPTimeoutMS default = %d, want 1500", cfg.HIBPTimeoutMS)
	}
}

func TestLoad_HIBPEnabled_AcceptsBooleanLike(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"true", true}, {"false", false},
		{"1", true}, {"0", false},
		{"TRUE", true},
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

func TestLoad_MissingRequiredVars(t *testing.T) {
	required := []string{
		"SCHLASS_DATABASE_URL",
		"SCHLASS_MIGRATIONS_DATABASE_URL",
		"SCHLASS_VALKEY_URL",
		"SCHLASS_ENCRYPTION_KEY",
	}
	for _, name := range required {
		t.Run(name, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv(name, "")
			_, err := Load()
			if err == nil {
				t.Fatalf("Load() with %s unset should fail", name)
			}
			if !strings.Contains(err.Error(), name) {
				t.Fatalf("error %q should mention missing var %q", err, name)
			}
		})
	}
}

func TestLoad_EncryptionKey_InvalidBase64(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SCHLASS_ENCRYPTION_KEY", "!!!not-base64!!!")
	if _, err := Load(); err == nil {
		t.Fatal("expected rejection of non-base64 key")
	}
}

func TestLoad_EncryptionKey_WrongLength(t *testing.T) {
	setRequiredEnv(t)
	short := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, 16))
	t.Setenv("SCHLASS_ENCRYPTION_KEY", short)
	_, err := Load()
	if err == nil {
		t.Fatal("expected rejection of 16-byte key")
	}
	if !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("error %q should mention 32-byte requirement", err)
	}
}

func TestLoad_RateLimits(t *testing.T) {
	knobs := []struct {
		env         string
		wantDefault int64
		get         func(*Env) int64
	}{
		{"SCHLASS_LOGIN_RATE_LIMIT", 5, func(c *Env) int64 { return c.LoginRateLimit }},
		{"SCHLASS_MFA_CHALLENGE_RATE_LIMIT", 5, func(c *Env) int64 { return c.MfaChallengeRateLimit }},
		{"SCHLASS_PASSWORD_RESET_RATE_LIMIT", 5, func(c *Env) int64 { return c.PasswordResetRateLimit }},
		{"SCHLASS_AUTHORIZE_RATE_LIMIT", 60, func(c *Env) int64 { return c.AuthorizeRateLimit }},
		{"SCHLASS_USERINFO_RATE_LIMIT", 60, func(c *Env) int64 { return c.UserinfoRateLimit }},
		{"SCHLASS_TOKEN_RATE_LIMIT", 60, func(c *Env) int64 { return c.TokenRateLimit }},
	}
	for _, k := range knobs {
		t.Run(k.env+"/default", func(t *testing.T) {
			setRequiredEnv(t)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := k.get(cfg); got != k.wantDefault {
				t.Fatalf("default = %d, want %d", got, k.wantDefault)
			}
		})
		t.Run(k.env+"/override", func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv(k.env, "123")
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := k.get(cfg); got != 123 {
				t.Fatalf("override = %d, want 123", got)
			}
		})
		t.Run(k.env+"/negative", func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv(k.env, "-1")
			if _, err := Load(); err == nil {
				t.Fatalf("%s=-1 should fail", k.env)
			}
		})
		t.Run(k.env+"/garbage", func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv(k.env, "nope")
			if _, err := Load(); err == nil {
				t.Fatalf("%s=nope should fail", k.env)
			}
		})
		t.Run(k.env+"/zero", func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv(k.env, "0")
			cfg, err := Load()
			if err != nil {
				t.Fatalf("%s=0 rejected: %v — Load must accept 0; rate-limiter semantics (block-all vs disabled) live in middleware", k.env, err)
			}
			if got := k.get(cfg); got != 0 {
				t.Fatalf("%s=0 got %d", k.env, got)
			}
		})
	}
}
