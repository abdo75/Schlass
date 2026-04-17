package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/config"
	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/database"
	"github.com/abdo75/Schlass/internal/middleware"
	"github.com/abdo75/Schlass/internal/model"
	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/store"
)

// AuditLogger is the narrow interface the auth handler needs from an audit
// store. Exported so the router wiring in cmd/schlass and the test harness
// can inject a fake without touching production code. *store.AuditStore
// already satisfies this interface.
type AuditLogger interface {
	Log(ctx context.Context, q database.Querier, entry store.AuditEntry) error
}

// AuthHandler serves POST /api/login (and, in later tasks, /api/logout and /api/me).
type AuthHandler struct {
	pool          *pgxpool.Pool
	sessionStore  session.Store
	userStore     *store.UserStore
	auditStore    AuditLogger
	configStore   *store.ConfigStore
	configService *config.ConfigService

	publicURL    string // for Origin check
	cookieSecure bool   // derived from publicURL at construction time

	dummyHash string // timing-defense Argon2id hash computed once at construction
}

// NewAuthHandler constructs the handler and pre-computes the dummy hash used
// by the user-not-found timing-defense path. Returns an error if the dummy
// hash cannot be computed so main.go can fail fast at startup.
func NewAuthHandler(
	pool *pgxpool.Pool,
	sessionStore session.Store,
	userStore *store.UserStore,
	auditStore AuditLogger,
	configStore *store.ConfigStore,
	configService *config.ConfigService,
	publicURL string,
) (*AuthHandler, error) {
	dummy, err := crypto.HashPassword("timing-defense-placeholder")
	if err != nil {
		return nil, fmt.Errorf("auth handler: pre-compute dummy hash: %w", err)
	}
	return &AuthHandler{
		pool:          pool,
		sessionStore:  sessionStore,
		userStore:     userStore,
		auditStore:    auditStore,
		configStore:   configStore,
		configService: configService,
		publicURL:     publicURL,
		cookieSecure:  strings.HasPrefix(publicURL, "https://"),
		dummyHash:     dummy,
	}, nil
}

func (h *AuthHandler) PostLogin(w http.ResponseWriter, r *http.Request) {
	// 1. Origin check — login CSRF defense.
	if r.Header.Get("Origin") != h.publicURL {
		writeError(w, http.StatusForbidden, "INVALID_ORIGIN", "Request origin not allowed.")
		return
	}

	// 2. Parse + validate body.
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if err := req.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	// 3. Read lockout policy from config (read-only, outside tx).
	threshold, err := h.configStore.GetInt(r.Context(), h.pool, "lockout_threshold")
	if err != nil {
		slog.Error("failed to read lockout_threshold", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	durationSecs, err := h.configStore.GetInt(r.Context(), h.pool, "lockout_duration_secs")
	if err != nil {
		slog.Error("failed to read lockout_duration_secs", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// TODO(post-sprint-2): consolidate clientIP implementations (duplicated in internal/middleware/ratelimit.go).
	ip := extractClientIP(r)

	// 4. Begin PG transaction — all state + audit writes live inside this tx.
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("failed to begin tx", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }() // non-actionable after a successful Commit (pgx returns ErrTxClosed)

	req.Email = strings.ToLower(req.Email)
	user, err := h.userStore.GetByEmail(r.Context(), tx, req.Email)
	if err != nil && !errors.Is(err, store.ErrUserNotFound) {
		slog.Error("GetByEmail failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if errors.Is(err, store.ErrUserNotFound) {
		// Enumeration defense: run VerifyPassword against the dummy hash so the
		// not-found path takes roughly the same wall time as the real path.
		_, _ = crypto.VerifyPassword(req.Password, h.dummyHash)

		if auditErr := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
			EventType:  "login.failed",
			ActorEmail: req.Email,
			TargetType: "user",
			IPAddress:  ip,
			Outcome:    "failure",
			Metadata:   map[string]any{"reason": "user_not_found"},
		}); auditErr != nil {
			slog.Error("audit write failed", "error", auditErr)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if commitErr := tx.Commit(r.Context()); commitErr != nil {
			slog.Error("commit failed", "error", commitErr)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password.")
		return
	}

	// 5. Pre-check lockout (user-side snapshot).
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		if auditErr := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
			EventType:  "login.failed",
			ActorID:    &user.ID,
			ActorEmail: user.Email,
			TargetType: "user",
			TargetID:   user.ID.String(),
			IPAddress:  ip,
			Outcome:    "failure",
			Metadata:   map[string]any{"reason": "locked"},
		}); auditErr != nil {
			slog.Error("audit write failed", "error", auditErr)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if commitErr := tx.Commit(r.Context()); commitErr != nil {
			slog.Error("commit failed", "error", commitErr)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		retryAfterSeconds := 0
		if d := time.Until(*user.LockedUntil); d > 0 {
			retryAfterSeconds = int(d.Seconds())
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error":               "ACCOUNT_LOCKED",
			"message":             "Account temporarily locked due to failed login attempts.",
			"retry_after_seconds": retryAfterSeconds,
		})
		return
	}

	// 6. Verify password.
	ok, verifyErr := crypto.VerifyPassword(req.Password, user.PasswordHash)
	if verifyErr != nil {
		slog.Error("VerifyPassword failed", "error", verifyErr)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if !ok {
		// Wrong password — increment counter + audit.
		newCount, locked, incErr := h.userStore.IncrementFailedLogins(
			r.Context(), tx, user.ID, threshold, durationSecs,
		)
		if errors.Is(incErr, store.ErrAlreadyLocked) {
			// Concurrent lock race: account was locked between our GetByEmail
			// and our UPDATE. Respond INVALID_CREDENTIALS (never leak the
			// locked-transition to a wrong-password attempt).
			if auditErr := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
				EventType:  "login.failed",
				ActorID:    &user.ID,
				ActorEmail: user.Email,
				TargetType: "user",
				TargetID:   user.ID.String(),
				IPAddress:  ip,
				Outcome:    "failure",
				Metadata:   map[string]any{"reason": "locked_concurrent"},
			}); auditErr != nil {
				slog.Error("audit write failed", "error", auditErr)
				writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
				return
			}
			if commitErr := tx.Commit(r.Context()); commitErr != nil {
				slog.Error("commit failed", "error", commitErr)
				writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
				return
			}
			writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password.")
			return
		}
		if incErr != nil {
			slog.Error("IncrementFailedLogins failed", "error", incErr)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}

		if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
			EventType:  "login.failed",
			ActorID:    &user.ID,
			ActorEmail: user.Email,
			TargetType: "user",
			TargetID:   user.ID.String(),
			IPAddress:  ip,
			Outcome:    "failure",
			Metadata:   map[string]any{"reason": "wrong_password", "failed_count": newCount},
		}); err != nil {
			slog.Error("audit write failed", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if locked {
			if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
				EventType:  "account.locked",
				ActorID:    &user.ID,
				ActorEmail: user.Email,
				TargetType: "user",
				TargetID:   user.ID.String(),
				IPAddress:  ip,
				Outcome:    "success",
				Metadata:   map[string]any{"threshold": threshold, "duration_secs": durationSecs},
			}); err != nil {
				slog.Error("audit write failed", "error", err)
				writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
				return
			}
		}
		if err := tx.Commit(r.Context()); err != nil {
			slog.Error("commit failed", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		// Same response whether this attempt just tripped the lock or not —
		// never leak the transition.
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password.")
		return
	}

	// 7. Success — reset counter, audit success, commit, create session.
	// ResetFailedLogins refuses to clear an active lock (Task 2's WHERE guard),
	// so a concurrent wrong-password attempt that locked the account between
	// our GetByEmail snapshot and this UPDATE flips us into ACCOUNT_LOCKED.
	resetErr := h.userStore.ResetFailedLogins(r.Context(), tx, user.ID)
	if errors.Is(resetErr, store.ErrAlreadyLocked) {
		// Re-read user inside the same tx to obtain the fresh locked_until.
		freshUser, freshErr := h.userStore.GetByID(r.Context(), tx, user.ID)
		if freshErr != nil {
			slog.Error("GetByID after race-lock failed", "error", freshErr)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if auditErr := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
			EventType:  "login.failed",
			ActorID:    &user.ID,
			ActorEmail: user.Email,
			TargetType: "user",
			TargetID:   user.ID.String(),
			IPAddress:  ip,
			Outcome:    "failure",
			Metadata:   map[string]any{"reason": "locked_race"},
		}); auditErr != nil {
			slog.Error("audit write failed", "error", auditErr)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if commitErr := tx.Commit(r.Context()); commitErr != nil {
			slog.Error("commit failed", "error", commitErr)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		retryAfterSeconds := 0
		if freshUser.LockedUntil != nil {
			retryAfterSeconds = int(time.Until(*freshUser.LockedUntil).Seconds())
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error":               "ACCOUNT_LOCKED",
			"message":             "Account temporarily locked due to failed login attempts.",
			"retry_after_seconds": retryAfterSeconds,
		})
		return
	}
	if resetErr != nil {
		slog.Error("ResetFailedLogins failed", "error", resetErr)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "login.succeeded",
		ActorID:    &user.ID,
		ActorEmail: user.Email,
		TargetType: "user",
		TargetID:   user.ID.String(),
		IPAddress:  ip,
		Outcome:    "success",
	}); err != nil {
		slog.Error("audit write failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("commit failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// 8. Post-tx: create session in Valkey, set cookie, return user.
	token, err := h.sessionStore.Create(r.Context(), user.ID.String(), ip, r.Header.Get("User-Agent"))
	if err != nil {
		slog.Error("session create failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "schlass_session",
		Value:    token,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteStrictMode,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"id":                    user.ID.String(),
			"email":                 user.Email,
			"role":                  user.Role,
			"force_password_change": user.ForcePasswordChange,
		},
	})
}

// PostLogout destroys the current session. Logout is a state change so the
// audit row is written inside a PG transaction (not best-effort); the Valkey
// session and cookie are cleared only after the tx commits. If the audit
// write or commit fails, the handler returns 500 and the user remains logged
// in — they retry, and a correct audit row lands on the second attempt.
func (h *AuthHandler) PostLogout(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.CurrentUser(r.Context())
	if !ok {
		// Defensive: /api/logout is auth-wrapped so this should be unreachable.
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}

	ip := extractClientIP(r)

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("failed to begin tx", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }() // non-actionable after a successful Commit (pgx returns ErrTxClosed)

	if auditErr := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "logout.completed",
		ActorID:    &user.ID,
		ActorEmail: user.Email,
		TargetType: "user",
		TargetID:   user.ID.String(),
		IPAddress:  ip,
		Outcome:    "success",
	}); auditErr != nil {
		slog.Error("audit write failed", "error", auditErr)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if commitErr := tx.Commit(r.Context()); commitErr != nil {
		slog.Error("commit failed", "error", commitErr)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Post-commit: destroy the Valkey session, then clear the cookie.
	// A missing cookie is tolerated (we still want to clear the client side),
	// but a Valkey delete error fails the request — the audit row already says
	// logout happened, so the user retries until the session is actually gone.
	if cookie, cookieErr := r.Cookie("schlass_session"); cookieErr == nil {
		if delErr := h.sessionStore.Delete(r.Context(), user.ID.String(), cookie.Value); delErr != nil {
			slog.Error("session delete failed", "error", delErr)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "schlass_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteStrictMode,
	})

	w.WriteHeader(http.StatusNoContent)
}

// changePasswordRequest is the decoded body for POST /api/change-password.
type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// PostChangePassword lets any authenticated user change their own password.
// Used both by the forced-password-change flow (temp password issued via
// admin reset) and as a self-service action. On success, the session token
// is rotated post-commit per OWASP Session Management guidance: the old
// token is destroyed and a new one issued, with the cookie updated inline
// so the user stays transparently logged in.
func (h *AuthHandler) PostChangePassword(w http.ResponseWriter, r *http.Request) {
	current, ok := middleware.CurrentUser(r.Context())
	if !ok {
		// Defensive: /api/change-password is auth-wrapped so this should be unreachable.
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}

	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}

	// 1. Verify current password. Treat mismatch as 400 WRONG_CURRENT_PASSWORD
	//    (not 401 — the session is still valid, the user just typed the wrong
	//    current password).
	verifyOK, verifyErr := crypto.VerifyPassword(req.CurrentPassword, current.PasswordHash)
	if verifyErr != nil {
		slog.Error("auth.PostChangePassword: verify current password", "error", verifyErr)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if !verifyOK {
		writeError(w, http.StatusBadRequest, "WRONG_CURRENT_PASSWORD", "Current password is incorrect.")
		return
	}

	// 2. Load policy + validate new password.
	policy, err := h.configService.GetPasswordPolicy(r.Context(), h.pool)
	if err != nil {
		slog.Error("auth.PostChangePassword: load password policy", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := model.ValidatePassword(req.NewPassword, policy); err != nil {
		var policyErr *model.PasswordPolicyError
		if errors.As(err, &policyErr) {
			writeError(w, http.StatusBadRequest, "PASSWORD_POLICY_VIOLATION", err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	// 3. Hash + persist inside a tx. force_password_change=false because the
	//    user is actively choosing this password.
	newHash, err := crypto.HashPassword(req.NewPassword)
	if err != nil {
		slog.Error("auth.PostChangePassword: hash new password", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	ip := extractClientIP(r)

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("auth.PostChangePassword: begin tx", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }() // non-actionable after commit (pgx returns ErrTxClosed)

	if err := h.userStore.SetPasswordHash(r.Context(), tx, current.ID, newHash, false); err != nil {
		slog.Error("auth.PostChangePassword: set password hash", "error", err, "user_id", current.ID) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if auditErr := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "password.changed",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "user",
		TargetID:   current.ID.String(),
		IPAddress:  ip,
		Outcome:    "success",
	}); auditErr != nil {
		slog.Error("audit password.changed write failed", "error", auditErr)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("auth.PostChangePassword: commit", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// 4. Post-commit: rotate the session token (OWASP Session Management —
	//    renew session identifier after credential change). Delete the
	//    caller's old session; if that fails, degrade to WARN and continue
	//    — an orphaned Valkey entry is less harmful than leaving the user
	//    with no working cookie.
	if oldCookie, cookieErr := r.Cookie("schlass_session"); cookieErr == nil {
		if delErr := h.sessionStore.Delete(r.Context(), current.ID.String(), oldCookie.Value); delErr != nil {
			slog.Warn("auth.PostChangePassword: old session delete degraded", "error", delErr, "user_id", current.ID) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		}
	}

	newToken, err := h.sessionStore.Create(r.Context(), current.ID.String(), ip, r.Header.Get("User-Agent"))
	if err != nil {
		// Password was committed but session rotation failed. Surface 500
		// so the client knows to re-authenticate; the user will log in with
		// the new password on their next attempt.
		slog.Error("auth.PostChangePassword: session rotate create failed (password was changed)", "error", err, "user_id", current.ID) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "schlass_session",
		Value:    newToken,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteStrictMode,
	})

	w.WriteHeader(http.StatusNoContent)
}

// GetMe returns the authenticated user DTO from the request context (populated
// by the auth middleware). Used by the frontend to rehydrate session state.
func (h *AuthHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.CurrentUser(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"id":                    user.ID.String(),
			"email":                 user.Email,
			"role":                  user.Role,
			"force_password_change": user.ForcePasswordChange,
		},
	})
}
