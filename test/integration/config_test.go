package integration

import (
	"context"
	"testing"

	"github.com/schlass/schlass/internal/config"
	"github.com/schlass/schlass/internal/store"
)

func TestConfigServiceNullHandling(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	configStore := store.NewConfigStore()
	encKey := []byte("test-encryption-key-32-bytes!!!!")
	configService := config.NewConfigService(configStore, encKey)

	// smtp_password is seeded as JSON null — should return empty string, not error
	val, err := configService.GetEncryptedValue(ctx, env.Pool, "smtp_password")
	if err != nil {
		t.Fatalf("GetEncryptedValue for null value should not error: %v", err)
	}
	if val != "" {
		t.Fatalf("expected empty string for null config value, got %q", val)
	}
}

func TestConfigServiceEncryptionRoundTrip(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	configStore := store.NewConfigStore()
	encKey := []byte("test-encryption-key-32-bytes!!!!")
	configService := config.NewConfigService(configStore, encKey)

	// Set an encrypted value
	err := configService.SetEncryptedValue(ctx, env.Pool, "smtp_password", "my-secret-smtp-pass")
	if err != nil {
		t.Fatalf("SetEncryptedValue failed: %v", err)
	}

	// Read it back — should decrypt to the original
	val, err := configService.GetEncryptedValue(ctx, env.Pool, "smtp_password")
	if err != nil {
		t.Fatalf("GetEncryptedValue failed: %v", err)
	}
	if val != "my-secret-smtp-pass" {
		t.Fatalf("expected 'my-secret-smtp-pass', got %q", val)
	}

	// Verify the raw stored value is NOT the plaintext (it should be base64-encoded ciphertext)
	rawVal, err := configStore.GetString(ctx, env.Pool, "smtp_password")
	if err != nil {
		t.Fatalf("GetString failed: %v", err)
	}
	if rawVal == "my-secret-smtp-pass" {
		t.Fatal("raw stored value should be encrypted, not plaintext")
	}
}

func TestConfigServicePasswordPolicy(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	configStore := store.NewConfigStore()
	encKey := []byte("test-encryption-key-32-bytes!!!!")
	configService := config.NewConfigService(configStore, encKey)

	policy, err := configService.GetPasswordPolicy(ctx, env.Pool)
	if err != nil {
		t.Fatalf("GetPasswordPolicy failed: %v", err)
	}

	// Verify defaults from seed data
	if policy.MinLength != 12 {
		t.Fatalf("expected MinLength=12, got %d", policy.MinLength)
	}
	if !policy.RequireUpper {
		t.Fatal("expected RequireUpper=true")
	}
	if !policy.RequireDigit {
		t.Fatal("expected RequireDigit=true")
	}
}
