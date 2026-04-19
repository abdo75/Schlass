package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL           string
	MigrationsDatabaseURL string
	ValkeyURL             string
	EncryptionKey         []byte
	Port                  string
	SchlassPublicURL      string
	// LoginRateLimit overrides the per-IP /api/login cap per minute. Zero
	// means "use the secure default" (5/min). Intended for E2E test runs
	// that need to burst past the default without disabling the limiter.
	LoginRateLimit int64
	// MfaChallengeRateLimit overrides the per-IP /api/mfa/challenge cap per
	// minute. Zero means "use the secure default" (5/min). Intended for E2E
	// test runs that need to burst past the default.
	MfaChallengeRateLimit int64
	// AuthorizeRateLimit overrides the per-IP GET /authorize cap per minute.
	// Zero means "use the secure default" (60/min). Intended for E2E test
	// runs that need to burst past the default.
	AuthorizeRateLimit int64
	// UserinfoRateLimit overrides the per-IP GET /userinfo cap per minute.
	// Zero means "use the secure default" (60/min). Intended for E2E test
	// runs that need to burst past the default.
	UserinfoRateLimit int64
}

func Load() (*Config, error) {
	_ = godotenv.Load() // .env file is optional; ignore if not present

	cfg := &Config{
		Port:             "3000",
		SchlassPublicURL: "http://localhost:3000",
	}

	var missing []string

	cfg.DatabaseURL = os.Getenv("SCHLASS_DATABASE_URL")
	if cfg.DatabaseURL == "" {
		missing = append(missing, "SCHLASS_DATABASE_URL")
	}

	cfg.MigrationsDatabaseURL = os.Getenv("SCHLASS_MIGRATIONS_DATABASE_URL")
	if cfg.MigrationsDatabaseURL == "" {
		missing = append(missing, "SCHLASS_MIGRATIONS_DATABASE_URL")
	}

	cfg.ValkeyURL = os.Getenv("SCHLASS_VALKEY_URL")
	if cfg.ValkeyURL == "" {
		missing = append(missing, "SCHLASS_VALKEY_URL")
	}

	encKeyB64 := os.Getenv("SCHLASS_ENCRYPTION_KEY")
	if encKeyB64 == "" {
		missing = append(missing, "SCHLASS_ENCRYPTION_KEY")
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %v", missing)
	}

	var err error
	cfg.EncryptionKey, err = base64.StdEncoding.DecodeString(encKeyB64)
	if err != nil {
		return nil, fmt.Errorf("SCHLASS_ENCRYPTION_KEY must be valid base64: %w", err)
	}
	if len(cfg.EncryptionKey) != 32 {
		return nil, fmt.Errorf("SCHLASS_ENCRYPTION_KEY must be 32 bytes (256-bit), got %d bytes", len(cfg.EncryptionKey))
	}

	if port := os.Getenv("SCHLASS_PORT"); port != "" {
		cfg.Port = port
	}

	if publicURL := os.Getenv("SCHLASS_PUBLIC_URL"); publicURL != "" {
		cfg.SchlassPublicURL = publicURL
	}

	if raw := os.Getenv("SCHLASS_LOGIN_RATE_LIMIT"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 0 {
			return nil, fmt.Errorf("SCHLASS_LOGIN_RATE_LIMIT must be a non-negative integer, got %q", raw)
		}
		cfg.LoginRateLimit = parsed
	}

	if raw := os.Getenv("SCHLASS_MFA_CHALLENGE_RATE_LIMIT"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 0 {
			return nil, fmt.Errorf("SCHLASS_MFA_CHALLENGE_RATE_LIMIT must be a non-negative integer, got %q", raw)
		}
		cfg.MfaChallengeRateLimit = parsed
	}

	if raw := os.Getenv("SCHLASS_AUTHORIZE_RATE_LIMIT"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 0 {
			return nil, fmt.Errorf("SCHLASS_AUTHORIZE_RATE_LIMIT must be a non-negative integer, got %q", raw)
		}
		cfg.AuthorizeRateLimit = parsed
	}

	if raw := os.Getenv("SCHLASS_USERINFO_RATE_LIMIT"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 0 {
			return nil, fmt.Errorf("SCHLASS_USERINFO_RATE_LIMIT must be a non-negative integer, got %q", raw)
		}
		cfg.UserinfoRateLimit = parsed
	}

	return cfg, nil
}
