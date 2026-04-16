package integration

import (
	"context"
	"testing"
	"time"

	"github.com/abdo75/Schlass/internal/store"
	"github.com/google/uuid"
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

func TestUserStore_List_PaginationAndSearch(t *testing.T) {
	ctx := context.Background()
	env := NewTestEnv(t)
	us := store.NewUserStore()

	// Seed 5 users.
	for _, email := range []string{"alice@example.com", "bob@example.com", "carol@example.com", "dave@example.com", "erin@example.com"} {
		if _, err := us.Create(ctx, env.Pool, email, "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$PLACEHOLDER", "user", false); err != nil {
			t.Fatalf("Create %s: %v", email, err)
		}
	}

	// Page 1, limit 3
	page, err := us.List(ctx, env.Pool, store.ListUsersParams{Limit: 3, Offset: 0})
	if err != nil {
		t.Fatalf("List page 1: %v", err)
	}
	if len(page.Users) != 3 {
		t.Fatalf("page 1 users: got %d want 3", len(page.Users))
	}
	if page.Total != 5 {
		t.Fatalf("total: got %d want 5", page.Total)
	}

	// Page 2, limit 3
	page2, _ := us.List(ctx, env.Pool, store.ListUsersParams{Limit: 3, Offset: 3})
	if len(page2.Users) != 2 {
		t.Fatalf("page 2 users: got %d want 2", len(page2.Users))
	}

	// Search matches partial email (case-insensitive)
	search, _ := us.List(ctx, env.Pool, store.ListUsersParams{Limit: 50, Offset: 0, EmailSearch: "ALI"})
	if len(search.Users) != 1 || search.Users[0].Email != "alice@example.com" {
		t.Fatalf("search result: got %+v", search.Users)
	}
}

func TestUserStore_Update(t *testing.T) {
	ctx := context.Background()
	env := NewTestEnv(t)
	us := store.NewUserStore()

	id, _ := us.Create(ctx, env.Pool, "old@example.com", "$argon2id$dummy", "user", false)

	if err := us.Update(ctx, env.Pool, id, "new@example.com", "super_admin"); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := us.GetByID(ctx, env.Pool, id)
	if got.Email != "new@example.com" {
		t.Fatalf("email: %q", got.Email)
	}
	if got.Role != "super_admin" {
		t.Fatalf("role: %q", got.Role)
	}
}

func TestUserStore_SetStatus(t *testing.T) {
	ctx := context.Background()
	env := NewTestEnv(t)
	us := store.NewUserStore()

	id, _ := us.Create(ctx, env.Pool, "user@example.com", "$argon2id$dummy", "user", false)
	if err := us.SetStatus(ctx, env.Pool, id, "disabled"); err != nil {
		t.Fatalf("SetStatus disabled: %v", err)
	}
	got, _ := us.GetByID(ctx, env.Pool, id)
	if got.Status != "disabled" {
		t.Fatalf("status: %q", got.Status)
	}

	_ = us.SetStatus(ctx, env.Pool, id, "active")
	got, _ = us.GetByID(ctx, env.Pool, id)
	if got.Status != "active" {
		t.Fatalf("status after re-enable: %q", got.Status)
	}
}

func TestUserStore_Delete(t *testing.T) {
	ctx := context.Background()
	env := NewTestEnv(t)
	us := store.NewUserStore()

	id, _ := us.Create(ctx, env.Pool, "gone@example.com", "$argon2id$dummy", "user", false)

	if err := us.Delete(ctx, env.Pool, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := us.GetByID(ctx, env.Pool, id)
	if err != store.ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound after delete, got %v", err)
	}
}

func TestUserStore_SetPasswordHash(t *testing.T) {
	ctx := context.Background()
	env := NewTestEnv(t)
	us := store.NewUserStore()

	id, _ := us.Create(ctx, env.Pool, "pwchange@example.com", "$argon2id$old", "user", false)

	if err := us.SetPasswordHash(ctx, env.Pool, id, "$argon2id$new", true); err != nil {
		t.Fatalf("SetPasswordHash: %v", err)
	}
	got, _ := us.GetByID(ctx, env.Pool, id)
	if got.PasswordHash != "$argon2id$new" {
		t.Fatalf("hash: %q", got.PasswordHash)
	}
	if !got.ForcePasswordChange {
		t.Fatal("force_password_change should be true after admin reset")
	}

	// Re-set with forcePasswordChange=false (user-initiated change)
	_ = us.SetPasswordHash(ctx, env.Pool, id, "$argon2id$newer", false)
	got, _ = us.GetByID(ctx, env.Pool, id)
	if got.ForcePasswordChange {
		t.Fatal("force_password_change should be false after user-initiated change")
	}
}

func TestUserStore_Update_UserNotFound(t *testing.T) {
	ctx := context.Background()
	env := NewTestEnv(t)
	us := store.NewUserStore()

	nonexistent := uuid.New()
	err := us.Update(ctx, env.Pool, nonexistent, "whatever@example.com", "user")
	if err != store.ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

func TestUserStore_List_EmailSearchEscapesMetacharacters(t *testing.T) {
	ctx := context.Background()
	env := NewTestEnv(t)
	us := store.NewUserStore()

	// Seed three users whose emails contain metacharacters literally
	if _, err := us.Create(ctx, env.Pool, "alice%match@example.com", "$argon2id$dummy", "user", false); err != nil {
		t.Fatalf("Create alice: %v", err)
	}
	if _, err := us.Create(ctx, env.Pool, "bob_match@example.com", "$argon2id$dummy", "user", false); err != nil {
		t.Fatalf("Create bob: %v", err)
	}
	if _, err := us.Create(ctx, env.Pool, "carol-match@example.com", "$argon2id$dummy", "user", false); err != nil {
		t.Fatalf("Create carol: %v", err)
	}

	// Searching for literal "%" should only match alice (not bob or carol)
	result, err := us.List(ctx, env.Pool, store.ListUsersParams{Limit: 50, Offset: 0, EmailSearch: "%match"})
	if err != nil {
		t.Fatalf("List with %% search: %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("literal %% search: want 1, got %d", result.Total)
	}
	if result.Users[0].Email != "alice%match@example.com" {
		t.Fatalf("want alice%%match, got %s", result.Users[0].Email)
	}

	// Searching for literal "_" should only match bob
	result2, err := us.List(ctx, env.Pool, store.ListUsersParams{Limit: 50, Offset: 0, EmailSearch: "_match"})
	if err != nil {
		t.Fatalf("List with _ search: %v", err)
	}
	if result2.Total != 1 {
		t.Fatalf("literal _ search: want 1, got %d", result2.Total)
	}
	if result2.Users[0].Email != "bob_match@example.com" {
		t.Fatalf("want bob_match, got %s", result2.Users[0].Email)
	}
}
