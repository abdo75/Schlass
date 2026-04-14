package config

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL           string
	MigrationsDatabaseURL string
	ValkeyURL             string
	EncryptionKey         []byte
	Port                  string
	SchlassPublicURL      string
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

	return cfg, nil
}
