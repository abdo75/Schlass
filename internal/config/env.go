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

// Default values for every Config field. 
// Override via the matching SCHLASS_* env var.
const (
	defaultPort             = "3000"
	defaultSchlassPublicURL = "http://localhost:3000"
	defaultHIBPEnabled      = true
	defaultHIBPEndpoint     = "https://api.pwnedpasswords.com/range"
	defaultHIBPTimeoutMS    = 1500
)

// Rate-limit defaults (per IP per minute). 
// int64 so they drop into the struct literal without a cast.
const (
	defaultLoginRateLimit         int64 = 5
	defaultMfaChallengeRateLimit  int64 = 5
	defaultPasswordResetRateLimit int64 = 5
	defaultAuthorizeRateLimit     int64 = 60
	defaultUserinfoRateLimit      int64 = 60
	defaultTokenRateLimit         int64 = 60 // per client_id per minute
)

type Config struct {
	DatabaseURL            string
	MigrationsDatabaseURL  string
	ValkeyURL              string
	EncryptionKey          []byte
	Port                   string
	SchlassPublicURL       string
	LoginRateLimit         int64
	MfaChallengeRateLimit  int64
	PasswordResetRateLimit int64
	AuthorizeRateLimit     int64
	UserinfoRateLimit      int64
	TokenRateLimit         int64
	HIBPEnabled            bool
	HIBPEndpoint           string
	HIBPTimeoutMS          int
}

func Load() (*Config, error) {
	_ = godotenv.Load() // Loads .env file if present

	cfg := &Config{
		Port:                   defaultPort,
		SchlassPublicURL:       defaultSchlassPublicURL,
		LoginRateLimit:         defaultLoginRateLimit,
		MfaChallengeRateLimit:  defaultMfaChallengeRateLimit,
		PasswordResetRateLimit: defaultPasswordResetRateLimit,
		AuthorizeRateLimit:     defaultAuthorizeRateLimit,
		UserinfoRateLimit:      defaultUserinfoRateLimit,
		TokenRateLimit:         defaultTokenRateLimit,
		HIBPEnabled:            defaultHIBPEnabled,
		HIBPEndpoint:           defaultHIBPEndpoint,
		HIBPTimeoutMS:          defaultHIBPTimeoutMS,
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

	if raw := os.Getenv("SCHLASS_TOKEN_RATE_LIMIT"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 0 {
			return nil, fmt.Errorf("SCHLASS_TOKEN_RATE_LIMIT must be a non-negative integer, got %q", raw)
		}
		cfg.TokenRateLimit = parsed
	}

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
