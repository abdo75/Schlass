package integration

import (
	"context"
	"testing"
	"time"

	"github.com/abdo75/Schlass/internal/store"
)

func TestUserStore_GetByEmail_GetByID(t *testing.T) {
	ctx := context.Background()
	env := NewTestEnv(t)

	us := store.NewUserStore()
	id, err := us.Create(ctx, env.Pool, "alice@example.com", "$argon2id$dummy", "super_admin", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	byEmail, err := us.GetByEmail(ctx, env.Pool, "alice@example.com")
	if err != nil {
		t.Fatalf("GetByEmail failed: %v", err)
	}
	if byEmail.ID != id {
		t.Fatalf("ID mismatch: got %v want %v", byEmail.ID, id)
	}
	if byEmail.Email != "alice@example.com" {
		t.Fatalf("email mismatch: %q", byEmail.Email)
	}

	byID, err := us.GetByID(ctx, env.Pool, id)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if byID.Email != "alice@example.com" {
		t.Fatalf("email mismatch via GetByID: %q", byID.Email)
	}

	_, err = us.GetByEmail(ctx, env.Pool, "nobody@example.com")
	if err != store.ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

func TestUserStore_IncrementFailedLogins_Lockout(t *testing.T) {
	ctx := context.Background()
	env := NewTestEnv(t)

	us := store.NewUserStore()
	id, _ := us.Create(ctx, env.Pool, "bob@example.com", "$argon2id$dummy", "super_admin", false)

	// Threshold 3, duration 60 seconds
	for i := 1; i <= 2; i++ {
		count, locked, err := us.IncrementFailedLogins(ctx, env.Pool, id, 3, 60)
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if locked {
			t.Fatalf("attempt %d: locked too early", i)
		}
		if count != i {
			t.Fatalf("attempt %d: count=%d, want %d", i, count, i)
		}
	}

	// Third attempt should lock
	count, locked, err := us.IncrementFailedLogins(ctx, env.Pool, id, 3, 60)
	if err != nil {
		t.Fatalf("lock attempt: %v", err)
	}
	if !locked {
		t.Fatal("expected locked=true on third attempt")
	}
	if count != 3 {
		t.Fatalf("count=%d, want 3", count)
	}

	// Fourth attempt while locked — must return ErrAlreadyLocked and NOT increment
	count, locked, err = us.IncrementFailedLogins(ctx, env.Pool, id, 3, 60)
	if err != store.ErrAlreadyLocked {
		t.Fatalf("expected ErrAlreadyLocked, got %v (count=%d locked=%v)", err, count, locked)
	}

	// Reset fails while still locked (race guard)
	if err := us.ResetFailedLogins(ctx, env.Pool, id); err != store.ErrAlreadyLocked {
		t.Fatalf("expected ErrAlreadyLocked from ResetFailedLogins on locked row, got %v", err)
	}

	// Fast-forward lock to the past, then reset succeeds
	if _, err := env.Pool.Exec(ctx,
		`UPDATE users SET locked_until = now() - interval '10 seconds' WHERE id = $1`, id,
	); err != nil {
		t.Fatalf("fast-forward locked_until: %v", err)
	}
	if err := us.ResetFailedLogins(ctx, env.Pool, id); err != nil {
		t.Fatalf("ResetFailedLogins after expiry: %v", err)
	}
	fresh, _ := us.GetByID(ctx, env.Pool, id)
	if fresh.FailedLoginAttempts != 0 {
		t.Fatalf("expected counter reset, got %d", fresh.FailedLoginAttempts)
	}
	if fresh.LockedUntil != nil && fresh.LockedUntil.After(time.Now()) {
		t.Fatalf("expected locked_until cleared, got %v", fresh.LockedUntil)
	}
}
