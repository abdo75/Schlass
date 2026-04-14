package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/abdo75/Schlass/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrUserNotFound  = errors.New("user: not found")
	ErrAlreadyLocked = errors.New("user: already locked")
)

// User is the full user row fetched by GetByID / GetByEmail.
// Fields mirror the users table (except TOTP fields, which are not needed
// by the auth handler in Sprint 2).
type User struct {
	ID                  uuid.UUID
	Email               string
	PasswordHash        string
	Role                string
	Status              string
	ForcePasswordChange bool
	FailedLoginAttempts int
	LockedUntil         *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type UserStore struct{}

func NewUserStore() *UserStore {
	return &UserStore{}
}

func (s *UserStore) Create(ctx context.Context, q database.Querier, email, passwordHash, role string, forcePasswordChange bool) (uuid.UUID, error) {
	var id uuid.UUID
	err := q.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, role, force_password_change)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id`,
		email, passwordHash, role, forcePasswordChange,
	).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("create user: %w", err)
	}
	return id, nil
}

const userSelectColumns = `id, email, password_hash, role, status,
force_password_change, failed_login_attempts, locked_until, created_at, updated_at`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	err := row.Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Status,
		&u.ForcePasswordChange, &u.FailedLoginAttempts, &u.LockedUntil,
		&u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &u, nil
}

func (s *UserStore) GetByEmail(ctx context.Context, q database.Querier, email string) (*User, error) {
	row := q.QueryRow(ctx,
		`SELECT `+userSelectColumns+` FROM users WHERE email = $1`,
		email,
	)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return u, nil
}

func (s *UserStore) GetByID(ctx context.Context, q database.Querier, id uuid.UUID) (*User, error) {
	row := q.QueryRow(ctx,
		`SELECT `+userSelectColumns+` FROM users WHERE id = $1`,
		id,
	)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return u, nil
}

// IncrementFailedLogins atomically increments failed_login_attempts and sets
// locked_until if the new count reaches threshold. The WHERE clause skips
// already-locked rows so concurrent attempts cannot double-count or
// double-audit the lockout transition.
//
// Returns (newCount, locked, nil) on a successful increment where locked=true
// iff this call was the one that tripped the lock.
// Returns (0, false, ErrAlreadyLocked) if the account was already locked at
// the time of the UPDATE — caller should respond ACCOUNT_LOCKED without a
// fresh account.locked audit row.
func (s *UserStore) IncrementFailedLogins(
	ctx context.Context,
	q database.Querier,
	userID uuid.UUID,
	threshold int,
	durationSecs int,
) (newCount int, locked bool, err error) {
	row := q.QueryRow(ctx, `
		UPDATE users
		SET failed_login_attempts = failed_login_attempts + 1,
		    locked_until = CASE
		        WHEN failed_login_attempts + 1 >= $2
		          THEN now() + make_interval(secs => $3)
		        ELSE locked_until
		    END,
		    updated_at = now()
		WHERE id = $1 AND (locked_until IS NULL OR locked_until < now())
		RETURNING
		    failed_login_attempts,
		    locked_until,
		    (locked_until IS NOT NULL AND locked_until > now()) AS just_locked
	`, userID, threshold, durationSecs)

	var lockedUntil *time.Time
	var justLocked bool
	if scanErr := row.Scan(&newCount, &lockedUntil, &justLocked); scanErr != nil {
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return 0, false, ErrAlreadyLocked
		}
		return 0, false, fmt.Errorf("increment failed logins: %w", scanErr)
	}
	return newCount, justLocked, nil
}

// ResetFailedLogins clears the counter and lock timestamp on successful login.
// It refuses to clear a lock that is currently active — if a concurrent
// wrong-password attempt locked the account between the handler's GetByEmail
// snapshot and this UPDATE, the row is skipped and ErrAlreadyLocked is
// returned. The handler must then respond ACCOUNT_LOCKED instead of 200,
// preserving the invariant that a locked account is locked for its full
// duration even across concurrent attempts.
func (s *UserStore) ResetFailedLogins(ctx context.Context, q database.Querier, userID uuid.UUID) error {
	tag, err := q.Exec(ctx, `
		UPDATE users
		SET failed_login_attempts = 0,
		    locked_until = NULL,
		    updated_at = now()
		WHERE id = $1 AND (locked_until IS NULL OR locked_until < now())
	`, userID)
	if err != nil {
		return fmt.Errorf("reset failed logins: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAlreadyLocked
	}
	return nil
}
