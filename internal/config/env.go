package config

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

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
	// PasswordResetRateLimit overrides per-IP /api/password-reset/request
	// cap per minute. Zero = 5/min default.
	PasswordResetRateLimit int64
	// AuthorizeRateLimit overrides the per-IP GET /authorize cap per minute.
	// Zero means "use the secure default" (60/min). Intended for E2E test
	// runs that need to burst past the default.
	AuthorizeRateLimit int64
	// UserinfoRateLimit overrides the per-IP GET /userinfo cap per minute.
	// Zero means "use the secure default" (60/min). Intended for E2E test
	// runs that need to burst past the default.
	UserinfoRateLimit int64
	// HIBPEnabled toggles the Have I Been Pwned breach-corpus check on
	// user-supplied passwords (setup, change-password, self-reset). Zero
	// / unset = true (on by default). Set SCHLASS_HIBP_ENABLED=false to
	// disable — intended for offline dev + integration tests.
	HIBPEnabled bool
	// HIBPEndpoint overrides the range-API base URL. Empty = production
	// https://api.pwnedpasswords.com/range. Tests set this to a httptest
	// server URL so they don't touch the real HIBP service.
	HIBPEndpoint string
	// HIBPTimeoutMS bounds the per-request HIBP HTTP call. Zero = 1500ms
	// (crypto.HIBPChecker default). Integration tests may lower it to
	// keep the suite fast when the stub is explicitly slow.
	HIBPTimeoutMS int
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
		u, err := url.Parse(publicURL)
		if err != nil {
			return nil, fmt.Errorf("SCHLASS_PUBLIC_URL: parse: %w", err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("SCHLASS_PUBLIC_URL must use http or https scheme, got %q", publicURL)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("SCHLASS_PUBLIC_URL must include a host, got %q", publicURL)
		}
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

	if raw := os.Getenv("SCHLASS_PASSWORD_RESET_RATE_LIMIT"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 0 {
			return nil, fmt.Errorf("SCHLASS_PASSWORD_RESET_RATE_LIMIT must be a non-negative integer, got %q", raw)
		}
		cfg.PasswordResetRateLimit = parsed
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

	cfg.HIBPEnabled = true
	if raw := os.Getenv("SCHLASS_HIBP_ENABLED"); raw != "" {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "false", "0", "off", "no":
			cfg.HIBPEnabled = false
		case "true", "1", "on", "yes":
			cfg.HIBPEnabled = true
		default:
			return nil, fmt.Errorf("SCHLASS_HIBP_ENABLED must be boolean-like (true/false), got %q", raw)
		}
	}
	if ep := os.Getenv("SCHLASS_HIBP_ENDPOINT"); ep != "" {
		cfg.HIBPEndpoint = ep
	}
	if raw := os.Getenv("SCHLASS_HIBP_TIMEOUT_MS"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return nil, fmt.Errorf("SCHLASS_HIBP_TIMEOUT_MS must be a non-negative integer, got %q", raw)
		}
		cfg.HIBPTimeoutMS = parsed
	}

	return cfg, nil
}
