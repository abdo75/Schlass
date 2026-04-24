// Package users owns the users table: the Store type and the User struct.
// Provides typed errors (ErrUserNotFound, ErrAlreadyLocked) and all read/write
// operations used by handlers and middleware. Caller owns the connection.
package users

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/abdo75/Schlass/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrUserNotFound  = errors.New("user: not found")
	ErrAlreadyLocked = errors.New("user: already locked")
)

type User struct {
	ID                  uuid.UUID
	Email               string
	PasswordHash        string
	Role                string
	Status              string
	ForcePasswordChange bool
	TOTPSecretEncrypted []byte
	TOTPEnrolledAt      *time.Time
	FailedLoginAttempts int
	LockedUntil         *time.Time
	LastUsedTOTPCounter int64
	LastLoginAt         *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type Store struct{}

func NewStore() *Store {
	return &Store{}
}

func (s *Store) Create(ctx context.Context, q database.Querier, email, passwordHash, role string, forcePasswordChange bool) (uuid.UUID, error) {
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
force_password_change, totp_secret_encrypted, totp_enrolled_at,
failed_login_attempts, locked_until, last_used_totp_counter,
last_login_at, created_at, updated_at`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	err := row.Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Status,
		&u.ForcePasswordChange, &u.TOTPSecretEncrypted, &u.TOTPEnrolledAt,
		&u.FailedLoginAttempts, &u.LockedUntil, &u.LastUsedTOTPCounter,
		&u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &u, nil
}

func (s *Store) GetByEmail(ctx context.Context, q database.Querier, email string) (*User, error) {
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

func (s *Store) GetByID(ctx context.Context, q database.Querier, id uuid.UUID) (*User, error) {
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

// IncrementFailedLogins: WHERE skips already-locked rows so concurrent
// attempts cannot double-count or double-audit. Returns:
//   - (newCount, locked=true, nil) when this call tripped the lock
//   - (newCount, locked=false, nil) on plain increment
//   - (0, false, ErrAlreadyLocked) when the row was already locked — caller
//     responds ACCOUNT_LOCKED without a fresh account.locked audit row.
func (s *Store) IncrementFailedLogins(
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

// ResetFailedLogins refuses to clear an active lock (returns ErrAlreadyLocked
// if a concurrent wrong-password attempt locked the row between snapshot and
// this UPDATE). Preserves the "locked account stays locked for full duration"
// invariant against concurrent races.
func (s *Store) ResetFailedLogins(ctx context.Context, q database.Querier, userID uuid.UUID) error {
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

// ClearLockoutForPasswordChange unconditionally clears the lock — unlike
// ResetFailedLogins, the caller has just successfully changed the password,
// which is a stronger signal than a successful login.
func (s *Store) ClearLockoutForPasswordChange(ctx context.Context, q database.Querier, userID uuid.UUID) error {
	_, err := q.Exec(ctx, `
		UPDATE users
		SET failed_login_attempts = 0,
		    locked_until = NULL,
		    updated_at = now()
		WHERE id = $1
	`, userID)
	if err != nil {
		return fmt.Errorf("clear lockout for password change: %w", err)
	}
	return nil
}

type ListUsersParams struct {
	Limit       int
	Offset      int
	EmailSearch string // empty = no filter; otherwise ILIKE '%<escaped>%'
}

type ListUsersResult struct {
	Users []*User
	Total int
}

func (s *Store) List(ctx context.Context, q database.Querier, params ListUsersParams) (*ListUsersResult, error) {
	if params.Limit <= 0 {
		params.Limit = 50
	}
	if params.Limit > 200 {
		params.Limit = 200
	}

	var (
		rows  pgx.Rows
		total int
		err   error
	)

	if params.EmailSearch == "" {
		if err := q.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&total); err != nil {
			return nil, fmt.Errorf("list users count: %w", err)
		}
		rows, err = q.Query(ctx,
			`SELECT `+userSelectColumns+` FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
			params.Limit, params.Offset,
		)
	} else {
		// Escape ILIKE metacharacters (% _) and the escape char itself so a
		// literal % or _ in the search string doesn't become a wildcard.
		escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(params.EmailSearch)
		pattern := "%" + escaped + "%"
		if err := q.QueryRow(ctx,
			`SELECT count(*) FROM users WHERE email ILIKE $1 ESCAPE '\'`, pattern,
		).Scan(&total); err != nil {
			return nil, fmt.Errorf("list users count (search): %w", err)
		}
		rows, err = q.Query(ctx,
			`SELECT `+userSelectColumns+` FROM users WHERE email ILIKE $1 ESCAPE '\' ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
			pattern, params.Limit, params.Offset,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("list users query: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var u User
		if err := rows.Scan(
			&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Status,
			&u.ForcePasswordChange, &u.TOTPSecretEncrypted, &u.TOTPEnrolledAt,
			&u.FailedLoginAttempts, &u.LockedUntil, &u.LastUsedTOTPCounter,
			&u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("list users scan: %w", err)
		}
		users = append(users, &u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list users rows: %w", err)
	}
	return &ListUsersResult{Users: users, Total: total}, nil
}

func (s *Store) Update(ctx context.Context, q database.Querier, id uuid.UUID, email, role string) error {
	tag, err := q.Exec(ctx,
		`UPDATE users SET email = $2, role = $3, updated_at = now() WHERE id = $1`,
		id, email, role,
	)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (s *Store) SetStatus(ctx context.Context, q database.Querier, id uuid.UUID, status string) error {
	tag, err := q.Exec(ctx,
		`UPDATE users SET status = $2, updated_at = now() WHERE id = $1`,
		id, status,
	)
	if err != nil {
		return fmt.Errorf("set status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// Delete requires migration 000011 (dropped audit_logs.actor_id FK) —
// otherwise FK-violates for users with audit history.
func (s *Store) Delete(ctx context.Context, q database.Querier, id uuid.UUID) error {
	tag, err := q.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (s *Store) SetPasswordHash(ctx context.Context, q database.Querier, id uuid.UUID, hash string, forcePasswordChange bool) error {
	tag, err := q.Exec(ctx,
		`UPDATE users SET password_hash = $2, force_password_change = $3, updated_at = now() WHERE id = $1`,
		id, hash, forcePasswordChange,
	)
	if err != nil {
		return fmt.Errorf("set password hash: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (s *Store) SetTOTPEnrolled(ctx context.Context, q database.Querier, userID uuid.UUID, encryptedSecret []byte) error {
	_, err := q.Exec(ctx,
		`UPDATE users SET totp_secret_encrypted = $1, totp_enrolled_at = now() WHERE id = $2`,
		encryptedSecret, userID)
	if err != nil {
		return fmt.Errorf("set totp enrolled: %w", err)
	}
	return nil
}

func (s *Store) ClearTOTP(ctx context.Context, q database.Querier, userID uuid.UUID) error {
	_, err := q.Exec(ctx,
		`UPDATE users SET totp_secret_encrypted = NULL, totp_enrolled_at = NULL, last_used_totp_counter = 0 WHERE id = $1`,
		userID)
	if err != nil {
		return fmt.Errorf("clear totp: %w", err)
	}
	return nil
}

// AdvanceTOTPCounter is a dumb setter — the gate (counter > previous) lives
// in the handler.
func (s *Store) AdvanceTOTPCounter(ctx context.Context, q database.Querier, userID uuid.UUID, counter int64) error {
	_, err := q.Exec(ctx,
		`UPDATE users SET last_used_totp_counter = $1 WHERE id = $2`,
		counter, userID)
	if err != nil {
		return fmt.Errorf("advance totp counter: %w", err)
	}
	return nil
}

// SetLastLoginAt: called inside the login.succeeded tx so the stamp + audit
// are atomic with the state change issuing the session cookie.
func (s *Store) SetLastLoginAt(ctx context.Context, q database.Querier, id uuid.UUID) error {
	tag, err := q.Exec(ctx,
		`UPDATE users SET last_login_at = now(), updated_at = now() WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("set last_login_at: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// GetEmail is lighter than GetByID — post-commit notify path needs only
// the email.
func (s *Store) GetEmail(ctx context.Context, q database.Querier, id uuid.UUID) (string, error) {
	var email string
	err := q.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, id).Scan(&email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrUserNotFound
		}
		return "", fmt.Errorf("get email: %w", err)
	}
	return email, nil
}
