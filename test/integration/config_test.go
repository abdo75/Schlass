//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/abdo75/Schlass/internal/config"
	"github.com/abdo75/Schlass/internal/store"
)

func TestInstanceConfigNullHandling(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	configStore := store.NewConfigStore()
	encKey := []byte("test-encryption-key-32-bytes!!!!")
	instanceConfig := config.NewInstanceConfig(configStore, encKey)

	// smtp_password is seeded as JSON null — should return empty string, not error
	val, err := instanceConfig.EncryptedValue(ctx, env.Pool, "smtp_password")
	if err != nil {
		t.Fatalf("EncryptedValue for null value should not error: %v", err)
	}
	if val != "" {
		t.Fatalf("expected empty string for null config value, got %q", val)
	}
}

func TestInstanceConfigEncryptionRoundTrip(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	configStore := store.NewConfigStore()
	encKey := []byte("test-encryption-key-32-bytes!!!!")
	instanceConfig := config.NewInstanceConfig(configStore, encKey)

	// Set an encrypted value
	err := instanceConfig.SetEncryptedValue(ctx, env.Pool, "smtp_password", "my-secret-smtp-pass")
	if err != nil {
		t.Fatalf("SetEncryptedValue failed: %v", err)
	}

	// Read it back — should decrypt to the original
	val, err := instanceConfig.EncryptedValue(ctx, env.Pool, "smtp_password")
	if err != nil {
		t.Fatalf("EncryptedValue failed: %v", err)
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

func TestInstanceConfigPasswordPolicy(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	configStore := store.NewConfigStore()
	encKey := []byte("test-encryption-key-32-bytes!!!!")
	instanceConfig := config.NewInstanceConfig(configStore, encKey)

	policy, err := instanceConfig.PasswordPolicy(ctx, env.Pool)
	if err != nil {
		t.Fatalf("PasswordPolicy failed: %v", err)
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
