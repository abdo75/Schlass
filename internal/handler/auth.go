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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/abdo75/Schlass/internal/config"
	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/database"
	"github.com/abdo75/Schlass/internal/middleware"
	"github.com/abdo75/Schlass/internal/model"
	"github.com/abdo75/Schlass/internal/revokebefore"
	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/store"
)

// AuditLogger is the narrow interface the auth handler needs from an audit
// store. Exported so the router wiring in cmd/schlass and the test harness
// can inject a fake without touching production code. *store.AuditStore
// already satisfies this interface.
type AuditLogger interface {
	Log(ctx context.Context, q database.Querier, entry store.AuditEntry) error
	// PseudonymizeUser is the GDPR Art. 17 compliance path. Replaces
	// actor_email with 'deleted:<uuid>' on every audit_logs row where
	// actor_id = userID. Dispatches to the audit_log_pseudonymize_user
	// SECURITY DEFINER SQL function (migration 000018). Returns rows
	// affected. Called only from the admin delete-user handler.
	PseudonymizeUser(ctx context.Context, q database.Querier, userID uuid.UUID) (int, error)
}

// AuthHandler serves POST /api/login (and, in later tasks, /api/logout and /api/me).
type AuthHandler struct {
	pool              *pgxpool.Pool
	valkey            *redis.Client
	sessionStore      session.Store
	userStore         *store.UserStore
	recoveryCodeStore *store.RecoveryCodeStore
	auditStore        AuditLogger
	configStore       *store.ConfigStore
	configService     *config.ConfigService

	publicURL    string // for Origin check
	cookieSecure bool   // derived from publicURL at construction time

	dummyHash   string             // timing-defense Argon2id hash computed once at construction
	hibpChecker *crypto.HIBPChecker // nil means HIBP check is disabled
}

// NewAuthHandler constructs the handler and pre-computes the dummy hash used
// by the user-not-found timing-defense path. Returns an error if the dummy
// hash cannot be computed so main.go can fail fast at startup.
func NewAuthHandler(
	pool *pgxpool.Pool,
	valkeyClient *redis.Client,
	sessionStore session.Store,
	userStore *store.UserStore,
	recoveryCodeStore *store.RecoveryCodeStore,
	auditStore AuditLogger,
	configStore *store.ConfigStore,
	configService *config.ConfigService,
	publicURL string,
	hibpChecker *crypto.HIBPChecker,
) (*AuthHandler, error) {
	dummy, err := crypto.HashPassword("timing-defense-placeholder")
	if err != nil {
		return nil, fmt.Errorf("auth handler: pre-compute dummy hash: %w", err)
	}
	return &AuthHandler{
		pool:              pool,
		valkey:            valkeyClient,
		sessionStore:      sessionStore,
		userStore:         userStore,
		recoveryCodeStore: recoveryCodeStore,
		auditStore:        auditStore,
		configStore:       configStore,
		configService:     configService,
		publicURL:         publicURL,
		cookieSecure:      isSecureURL(publicURL),
		dummyHash:         dummy,
		hibpChecker:       hibpChecker,
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

	// 2a. Sanitize an optional return_to. Fail-closed: an invalid value is
	// silently dropped rather than rejected, so a malformed deep link does
	// not block login. Only the canonical relative form is threaded
	// further; downstream carriers never see the raw input.
	sanitizedReturnTo := ""
	if req.ReturnTo != "" {
		if clean, ok := SanitizeReturnTo(req.ReturnTo, h.publicURL); ok {
			sanitizedReturnTo = clean
		}
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

	// 8. Branch order per spec §4a:
	//   (a) force_password_change=true → issue session, skip MFA check.
	//       AuthGuard routes to /change-password; MFA state is re-evaluated
	//       after the change (refreshUser + AuthGuard's force_mfa_enrollment
	//       redirect fires naturally).
	//   (b) mfa_required + not enrolled → enrollment flow (no session yet)
	//   (c) mfa_required + enrolled → challenge flow (no session yet)
	//   (d) no MFA → legacy flow (session issued immediately)
	//
	// Ordering (a) FIRST means a user with a temp password completes password
	// rotation BEFORE MFA enrollment. Temp passwords aren't real credentials;
	// enrolling MFA against a temp password would tie the authenticator to a
	// credential that's about to change.
	if user.ForcePasswordChange {
		// Audit-in-tx: login.succeeded fires here, inside the same tx as
		// ResetFailedLogins above, before any Valkey side-effect.
		if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
			EventType:  "login.succeeded",
			ActorID:    &user.ID,
			ActorEmail: user.Email,
			TargetType: "user",
			TargetID:   user.ID.String(),
			IPAddress:  ip,
			Outcome:    "success",
			Metadata:   map[string]any{"force_password_change_pending": true},
		}); err != nil {
			slog.Error("audit login.succeeded failed (force-pw branch)", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if err := h.userStore.SetLastLoginAt(r.Context(), tx, user.ID); err != nil {
			slog.Error("login: SetLastLoginAt failed (force-pw branch)", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			slog.Error("login: commit failed (force-pw branch)", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		sessionToken, err := h.sessionStore.CreateWithPendingReturnTo(
			r.Context(), user.ID.String(), ip, r.Header.Get("User-Agent"), sanitizedReturnTo,
		)
		if err != nil {
			slog.Error("login: session.Create failed (force-pw branch)", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		setSessionCookie(w, sessionToken, h.cookieSecure)
		// redirect_to is NOT emitted here — the caller must first rotate the
		// temp password. It resurfaces on /api/change-password success.
		writeJSON(w, http.StatusOK, map[string]any{"user": userDTO(user)})
		return
	}

	// From here, user.ForcePasswordChange is false. Consult MFA state next.
	mfaRequired, err := h.configStore.GetBool(r.Context(), tx, "mfa_required")
	if err != nil {
		slog.Error("login: mfa_required read failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	switch {
	case mfaRequired && user.TOTPEnrolledAt == nil:
		// Enrollment required — commit the password-side work (ResetFailedLogins)
		// without writing login.succeeded; that audit row moves to /enrollment/complete.
		if err := tx.Commit(r.Context()); err != nil {
			slog.Error("login: commit failed (enroll branch)", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		enrollToken, err := generateRandomToken(32)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		key := "mfa:enroll:" + enrollToken
		enrollFields := []any{"user_id", user.ID.String()}
		if sanitizedReturnTo != "" {
			enrollFields = append(enrollFields, "return_to", sanitizedReturnTo)
		}
		if err := h.valkey.HSet(r.Context(), key, enrollFields...).Err(); err != nil {
			slog.Error("login: Valkey HSet enroll token failed", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		h.valkey.Expire(r.Context(), key, 10*time.Minute)
		http.SetCookie(w, &http.Cookie{
			Name:     "schlass_mfa_enroll",
			Value:    enrollToken,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   h.cookieSecure,
			MaxAge:   600, // 10 min
		})
		writeJSON(w, http.StatusAccepted, map[string]any{"totp_enrollment_required": true})

	case mfaRequired && user.TOTPEnrolledAt != nil:
		// Challenge required — commit the password-side work without login.succeeded;
		// that audit row moves to /api/mfa/challenge on success.
		if err := tx.Commit(r.Context()); err != nil {
			slog.Error("login: commit failed (challenge branch)", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		challengeToken, err := generateRandomToken(32)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		key := "mfa:challenge:" + challengeToken
		challengeFields := []any{
			"user_id", user.ID.String(),
			"attempts_remaining", 5,
		}
		if sanitizedReturnTo != "" {
			challengeFields = append(challengeFields, "return_to", sanitizedReturnTo)
		}
		if err := h.valkey.HSet(r.Context(), key, challengeFields...).Err(); err != nil {
			slog.Error("login: Valkey HSet challenge token failed", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		h.valkey.Expire(r.Context(), key, 120*time.Second)
		http.SetCookie(w, &http.Cookie{
			Name:     "schlass_mfa_challenge",
			Value:    challengeToken,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   h.cookieSecure,
			MaxAge:   120,
		})
		writeJSON(w, http.StatusAccepted, map[string]any{"totp_required": true})

	default:
		// No MFA required — legacy path. login.succeeded fires here.
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
		if err := h.userStore.SetLastLoginAt(r.Context(), tx, user.ID); err != nil {
			slog.Error("login: SetLastLoginAt failed (no-mfa branch)", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			slog.Error("login: commit failed", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		sessionToken, err := h.sessionStore.Create(r.Context(), user.ID.String(), ip, r.Header.Get("User-Agent"))
		if err != nil {
			slog.Error("login: session.Create failed", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		setSessionCookie(w, sessionToken, h.cookieSecure)
		resp := map[string]any{"user": userDTO(user)}
		if sanitizedReturnTo != "" {
			resp["redirect_to"] = sanitizedReturnTo
		}
		writeJSON(w, http.StatusOK, resp)
	}
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
		SameSite: http.SameSiteLaxMode,
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

	// Pull the current session's PendingReturnTo (if any) BEFORE any
	// mutation. The upcoming rotate-on-success path destroys the old
	// session, so this is the last opportunity to read the value.
	pendingReturnTo := ""
	if oldCookie, cookieErr := r.Cookie("schlass_session"); cookieErr == nil {
		if sess, err := h.sessionStore.Get(r.Context(), oldCookie.Value); err == nil && sess != nil {
			pendingReturnTo = sess.PendingReturnTo
		}
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

	// 2a. HIBP breach-corpus check (NIST SP 800-63B-4 §3.1.1.2). Fail-open
	//    on network error — HIBP outages must not block password changes.
	if pwned, hibpErr := h.hibpChecker.IsPwned(r.Context(), req.NewPassword); hibpErr != nil {
		slog.Warn("password_breach_check: hibp unavailable", "error", hibpErr)
	} else if pwned {
		writeError(w, http.StatusBadRequest, "PASSWORD_BREACHED",
			"This password has appeared in a known data breach. Choose a different one.")
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

	// Revoke all OIDC tokens issued before this moment (spec §5g).
	if auditErr := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "user.revoke_before_set",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "user",
		TargetID:   current.ID.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"reason": "self_change_password"},
	}); auditErr != nil {
		slog.Error("audit user.revoke_before_set (self_change_password)", "error", auditErr)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("auth.PostChangePassword: commit", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// 4. Post-commit: set revoke_before so OIDC tokens issued before the
	//    password change are rejected at /token refresh and /userinfo.
	if err := revokebefore.SetNow(r.Context(), h.valkey, current.ID.String()); err != nil {
		slog.Error("auth.PostChangePassword: revoke_before Valkey write failed", "error", err, "user_id", current.ID) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
	}

	// 5. Post-commit: rotate the session token (OWASP Session Management —
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
		// See setSessionCookie in response.go for the Lax rationale (OIDC
		// /authorize is an entry point for cross-site top-level redirects).
		SameSite: http.SameSiteLaxMode,
	})

	// The old session (and its PendingReturnTo) was already destroyed above,
	// and the new session is minted via plain Create — no explicit clear
	// required. Emit redirect_to in the success response when the original
	// session carried one; otherwise return an empty JSON object so the SPA
	// can branch on presence without worrying about 204 vs 200.
	resp := map[string]any{}
	if pendingReturnTo != "" {
		resp["redirect_to"] = pendingReturnTo
	}
	writeJSON(w, http.StatusOK, resp)
}

// PostDisableMfa handles POST /api/me/mfa/disable — self-service MFA disable.
// Requires the authenticated user to re-enter their password as proof of
// possession. On success:
//   - Clears totp_secret_encrypted, totp_enrolled_at, last_used_totp_counter
//   - Deletes all recovery codes
//   - Writes mfa.self_reset audit row
//   - Revokes all Valkey sessions for the user (including the current one)
//
// Re-auth via password only (not password + current TOTP) — consistent with
// POST /api/change-password which also requires only password.
func (h *AuthHandler) PostDisableMfa(w http.ResponseWriter, r *http.Request) {
	current, ok := middleware.CurrentUser(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}

	if current.TOTPEnrolledAt == nil {
		writeError(w, http.StatusBadRequest, "MFA_NOT_ENROLLED", "Two-factor authentication is not enabled on this account.")
		return
	}

	// Verify password. Load the full user (middleware may only have a subset)
	// so we have the password_hash.
	full, err := h.userStore.GetByID(r.Context(), h.pool, current.ID)
	if err != nil {
		slog.Error("disable-mfa: GetByID failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	ok2, err := crypto.VerifyPassword(req.CurrentPassword, full.PasswordHash)
	if err != nil {
		slog.Error("disable-mfa: VerifyPassword failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if !ok2 {
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid password.")
		return
	}

	// Tx: clear TOTP + delete recovery codes + audit, atomic commit.
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	deleted, err := h.recoveryCodeStore.DeleteAllForUser(r.Context(), tx, current.ID)
	if err != nil {
		slog.Error("disable-mfa: DeleteAllForUser failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.userStore.ClearTOTP(r.Context(), tx, current.ID); err != nil {
		slog.Error("disable-mfa: ClearTOTP failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	wasEnrolledAt := current.TOTPEnrolledAt.Format(time.RFC3339)
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "mfa.self_reset",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "user",
		TargetID:   current.ID.String(),
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata: map[string]any{
			"recovery_codes_burned": deleted,
			"was_enrolled_at":       wasEnrolledAt,
		},
	}); err != nil {
		slog.Error("disable-mfa: audit write failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Revoke all OIDC tokens issued before this moment (spec §5g).
	if auditErr := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "user.revoke_before_set",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "user",
		TargetID:   current.ID.String(),
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata:   map[string]any{"reason": "self_disable_mfa"},
	}); auditErr != nil {
		slog.Error("audit user.revoke_before_set (self_disable_mfa)", "error", auditErr)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("disable-mfa: Commit failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Post-tx: revoke ALL sessions for this user (including the current one).
	if err := h.sessionStore.DeleteAllForUser(r.Context(), current.ID.String()); err != nil {
		slog.Error("disable-mfa: session revocation failed", "error", err, "user_id", current.ID)
		// Non-fatal — the PG state is committed, audit row is written.
	}
	// Post-commit, best-effort: set revoke_before so OIDC tokens issued
	// before the self MFA disable are rejected at /token refresh and /userinfo.
	if err := revokebefore.SetNow(r.Context(), h.valkey, current.ID.String()); err != nil {
		slog.Error("disable-mfa: revoke_before Valkey write failed", "error", err, "user_id", current.ID) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
	}

	// Clear the session cookie client-side too.
	http.SetCookie(w, &http.Cookie{
		Name:     "schlass_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.cookieSecure,
		MaxAge:   -1,
	})

	writeJSON(w, http.StatusOK, map[string]any{"disabled": true})
}

// GetMe returns the authenticated user DTO from the request context (populated
// by the auth middleware). Used by the frontend to rehydrate session state.
// It also includes force_mfa_enrollment so the SPA AuthGuard can redirect to
// /setup-mfa when the user has not yet enrolled and MFA is required.
func (h *AuthHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.CurrentUser(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}

	mfaRequired, err := h.configStore.GetBool(r.Context(), h.pool, "mfa_required")
	if err != nil {
		slog.Error("GetMe: mfa_required read failed", "error", err)
		mfaRequired = true // fail-safe — treat as required
	}
	forceMFAEnrollment := mfaRequired && user.TOTPEnrolledAt == nil

	dto := userDTO(user)
	dto["force_mfa_enrollment"] = forceMFAEnrollment

	// Include recovery code count when the user is enrolled. Best-effort:
	// a failure here (e.g. transient DB error) degrades to omitting the count
	// rather than returning a 500, since it is display-only metadata.
	if user.TOTPEnrolledAt != nil {
		count, err := h.recoveryCodeStore.CountUnused(r.Context(), h.pool, user.ID)
		if err != nil {
			slog.Error("GetMe: CountUnused recovery codes failed", "error", err)
		} else {
			dto["mfa"] = map[string]any{"unused_recovery_codes": count}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"user": dto})
}
