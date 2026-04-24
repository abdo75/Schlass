package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/abdo75/Schlass/internal/apierrors"
	"github.com/abdo75/Schlass/internal/audit"
	
	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/httputil"
	"github.com/abdo75/Schlass/internal/instanceconfig"
	"github.com/abdo75/Schlass/internal/oidc"
	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/users"
	"github.com/abdo75/Schlass/internal/validate"
)

// AuditLogger is injected so the router and tests can swap the real
// *audit.Store for a fake. PseudonymizeUser is the GDPR Art. 17 path —
// the only sanctioned mutation on audit_logs.
//
// Deprecated: prefer audit.PseudonymizingLogger directly. This alias
// is kept for integration-test compat (testutil.go references handler.AuditLogger
// via the shim in internal/handler/).
type AuditLogger = audit.PseudonymizingLogger

// Handler is the first-party session handler: login, logout,
// change-password, disable-MFA, and /api/me.
type Handler struct {
	pool              *pgxpool.Pool
	valkey            *redis.Client
	sessionStore      session.Store
	userStore         *users.Store
	recoveryCodeStore *RecoveryCodeStore
	auditStore        AuditLogger
	configStore       *instanceconfig.Store
	instanceConfig    *instanceconfig.Service

	publicURL    string
	cookieSecure bool

	dummyHash   string // pre-computed once so unknown-email path's Argon2id cost matches the real path
	hibpChecker *crypto.HIBPChecker
}

func NewHandler(
	pool *pgxpool.Pool,
	valkeyClient *redis.Client,
	sessionStore session.Store,
	userStore *users.Store,
	recoveryCodeStore *RecoveryCodeStore,
	auditStore AuditLogger,
	configStore *instanceconfig.Store,
	instanceConfig *instanceconfig.Service,
	publicURL string,
	hibpChecker *crypto.HIBPChecker,
) (*Handler, error) {
	dummy, err := crypto.HashPassword("timing-defense-placeholder")
	if err != nil {
		return nil, fmt.Errorf("auth handler: pre-compute dummy hash: %w", err)
	}
	return &Handler{
		pool:              pool,
		valkey:            valkeyClient,
		sessionStore:      sessionStore,
		userStore:         userStore,
		recoveryCodeStore: recoveryCodeStore,
		auditStore:        auditStore,
		configStore:       configStore,
		instanceConfig:    instanceConfig,
		publicURL:         publicURL,
		cookieSecure:      session.IsSecureURL(publicURL),
		dummyHash:         dummy,
		hibpChecker:       hibpChecker,
	}, nil
}

func (h *Handler) PostLogin(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != h.publicURL {
		httputil.WriteError(w, http.StatusForbidden, "INVALID_ORIGIN", "Request origin not allowed.")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if err := req.Validate(); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	sanitizedReturnTo := ""
	if req.ReturnTo != "" {
		if clean, ok := oidc.SanitizeReturnTo(req.ReturnTo, h.publicURL); ok {
			sanitizedReturnTo = clean
		}
	}

	threshold, err := h.configStore.GetInt(r.Context(), h.pool, "lockout_threshold")
	if err != nil {
		slog.Error("failed to read lockout_threshold", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	durationSecs, err := h.configStore.GetInt(r.Context(), h.pool, "lockout_duration_secs")
	if err != nil {
		slog.Error("failed to read lockout_duration_secs", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	ip := extractClientIP(r)

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("failed to begin tx", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	req.Email = strings.ToLower(req.Email)
	u, err := h.userStore.GetByEmail(r.Context(), tx, req.Email)
	if err != nil && !errors.Is(err, users.ErrUserNotFound) {
		slog.Error("GetByEmail failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if errors.Is(err, users.ErrUserNotFound) {
		// Enumeration defense: run VerifyPassword against the dummy hash so
		// this path takes roughly the same wall time as the real path.
		_, _ = crypto.VerifyPassword(req.Password, h.dummyHash)

		if auditErr := h.auditStore.Log(r.Context(), tx, audit.Entry{
			EventType:  "login.failed",
			ActorEmail: req.Email,
			TargetType: "user",
			IPAddress:  ip,
			Outcome:    "failure",
			Metadata:   map[string]any{"reason": "user_not_found"},
		}); auditErr != nil {
			slog.Error("audit write failed", "error", auditErr)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if commitErr := tx.Commit(r.Context()); commitErr != nil {
			slog.Error("commit failed", "error", commitErr)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password.")
		return
	}

	if u.LockedUntil != nil && u.LockedUntil.After(time.Now()) {
		if auditErr := h.auditStore.Log(r.Context(), tx, audit.Entry{
			EventType:  "login.failed",
			ActorID:    &u.ID,
			ActorEmail: u.Email,
			TargetType: "user",
			TargetID:   u.ID.String(),
			IPAddress:  ip,
			Outcome:    "failure",
			Metadata:   map[string]any{"reason": "locked"},
		}); auditErr != nil {
			slog.Error("audit write failed", "error", auditErr)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if commitErr := tx.Commit(r.Context()); commitErr != nil {
			slog.Error("commit failed", "error", commitErr)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		retryAfterSeconds := 0
		if d := time.Until(*u.LockedUntil); d > 0 {
			retryAfterSeconds = int(d.Seconds())
		}
		httputil.WriteJSON(w, http.StatusUnauthorized, map[string]any{
			"error":               "ACCOUNT_LOCKED",
			"message":             "Account temporarily locked due to failed login attempts.",
			"retry_after_seconds": retryAfterSeconds,
		})
		return
	}

	ok, verifyErr := crypto.VerifyPassword(req.Password, u.PasswordHash)
	if verifyErr != nil {
		slog.Error("VerifyPassword failed", "error", verifyErr)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if !ok {
		newCount, locked, incErr := h.userStore.IncrementFailedLogins(
			r.Context(), tx, u.ID, threshold, durationSecs,
		)
		if errors.Is(incErr, users.ErrAlreadyLocked) {
			if auditErr := h.auditStore.Log(r.Context(), tx, audit.Entry{
				EventType:  "login.failed",
				ActorID:    &u.ID,
				ActorEmail: u.Email,
				TargetType: "user",
				TargetID:   u.ID.String(),
				IPAddress:  ip,
				Outcome:    "failure",
				Metadata:   map[string]any{"reason": "locked_concurrent"},
			}); auditErr != nil {
				slog.Error("audit write failed", "error", auditErr)
				httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
				return
			}
			if commitErr := tx.Commit(r.Context()); commitErr != nil {
				slog.Error("commit failed", "error", commitErr)
				httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
				return
			}
			httputil.WriteError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password.")
			return
		}
		if incErr != nil {
			slog.Error("IncrementFailedLogins failed", "error", incErr)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}

		if err := h.auditStore.Log(r.Context(), tx, audit.Entry{
			EventType:  "login.failed",
			ActorID:    &u.ID,
			ActorEmail: u.Email,
			TargetType: "user",
			TargetID:   u.ID.String(),
			IPAddress:  ip,
			Outcome:    "failure",
			Metadata:   map[string]any{"reason": "wrong_password", "failed_count": newCount},
		}); err != nil {
			slog.Error("audit write failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if locked {
			if err := h.auditStore.Log(r.Context(), tx, audit.Entry{
				EventType:  "account.locked",
				ActorID:    &u.ID,
				ActorEmail: u.Email,
				TargetType: "user",
				TargetID:   u.ID.String(),
				IPAddress:  ip,
				Outcome:    "success",
				Metadata:   map[string]any{"threshold": threshold, "duration_secs": durationSecs},
			}); err != nil {
				slog.Error("audit write failed", "error", err)
				httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
				return
			}
		}
		if err := tx.Commit(r.Context()); err != nil {
			slog.Error("commit failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password.")
		return
	}

	resetErr := h.userStore.ResetFailedLogins(r.Context(), tx, u.ID)
	if errors.Is(resetErr, users.ErrAlreadyLocked) {
		freshUser, freshErr := h.userStore.GetByID(r.Context(), tx, u.ID)
		if freshErr != nil {
			slog.Error("GetByID after race-lock failed", "error", freshErr)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if auditErr := h.auditStore.Log(r.Context(), tx, audit.Entry{
			EventType:  "login.failed",
			ActorID:    &u.ID,
			ActorEmail: u.Email,
			TargetType: "user",
			TargetID:   u.ID.String(),
			IPAddress:  ip,
			Outcome:    "failure",
			Metadata:   map[string]any{"reason": "locked_race"},
		}); auditErr != nil {
			slog.Error("audit write failed", "error", auditErr)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if commitErr := tx.Commit(r.Context()); commitErr != nil {
			slog.Error("commit failed", "error", commitErr)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		retryAfterSeconds := 0
		if freshUser.LockedUntil != nil {
			retryAfterSeconds = int(time.Until(*freshUser.LockedUntil).Seconds())
		}
		httputil.WriteJSON(w, http.StatusUnauthorized, map[string]any{
			"error":               "ACCOUNT_LOCKED",
			"message":             "Account temporarily locked due to failed login attempts.",
			"retry_after_seconds": retryAfterSeconds,
		})
		return
	}
	if resetErr != nil {
		slog.Error("ResetFailedLogins failed", "error", resetErr)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Branch order is load-bearing: force_password_change FIRST so a user
	// with a temp password rotates it BEFORE binding an authenticator.
	// Enrolling MFA against a credential that's about to change is wrong.
	if u.ForcePasswordChange {
		if err := h.auditStore.Log(r.Context(), tx, audit.Entry{
			EventType:  "login.succeeded",
			ActorID:    &u.ID,
			ActorEmail: u.Email,
			TargetType: "user",
			TargetID:   u.ID.String(),
			IPAddress:  ip,
			Outcome:    "success",
			Metadata:   map[string]any{"force_password_change_pending": true},
		}); err != nil {
			slog.Error("audit login.succeeded failed (force-pw branch)", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if err := h.userStore.SetLastLoginAt(r.Context(), tx, u.ID); err != nil {
			slog.Error("login: SetLastLoginAt failed (force-pw branch)", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			slog.Error("login: commit failed (force-pw branch)", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		sessionToken, err := h.sessionStore.CreateWithPendingReturnTo(
			r.Context(), u.ID.String(), ip, r.Header.Get("User-Agent"), sanitizedReturnTo,
		)
		if err != nil {
			slog.Error("login: session.Create failed (force-pw branch)", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		session.SetCookie(w, sessionToken, h.cookieSecure)
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"user": userDTO(u)})
		return
	}

	mfaRequired, err := h.configStore.GetBool(r.Context(), tx, "mfa_required")
	if err != nil {
		slog.Error("login: mfa_required read failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	switch {
	case mfaRequired && u.TOTPEnrolledAt == nil:
		if err := tx.Commit(r.Context()); err != nil {
			slog.Error("login: commit failed (enroll branch)", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		enrollToken, err := crypto.RandomToken(32)
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		key := "mfa:enroll:" + enrollToken
		enrollFields := []any{"user_id", u.ID.String()}
		if sanitizedReturnTo != "" {
			enrollFields = append(enrollFields, "return_to", sanitizedReturnTo)
		}
		if err := h.valkey.HSet(r.Context(), key, enrollFields...).Err(); err != nil {
			slog.Error("login: Valkey HSet enroll token failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
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
			MaxAge:   600,
		})
		httputil.WriteJSON(w, http.StatusAccepted, map[string]any{"totp_enrollment_required": true})

	case mfaRequired && u.TOTPEnrolledAt != nil:
		if err := tx.Commit(r.Context()); err != nil {
			slog.Error("login: commit failed (challenge branch)", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		challengeToken, err := crypto.RandomToken(32)
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		key := "mfa:challenge:" + challengeToken
		challengeFields := []any{
			"user_id", u.ID.String(),
			"attempts_remaining", 5,
		}
		if sanitizedReturnTo != "" {
			challengeFields = append(challengeFields, "return_to", sanitizedReturnTo)
		}
		if err := h.valkey.HSet(r.Context(), key, challengeFields...).Err(); err != nil {
			slog.Error("login: Valkey HSet challenge token failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
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
		httputil.WriteJSON(w, http.StatusAccepted, map[string]any{"totp_required": true})

	default:
		if err := h.auditStore.Log(r.Context(), tx, audit.Entry{
			EventType:  "login.succeeded",
			ActorID:    &u.ID,
			ActorEmail: u.Email,
			TargetType: "user",
			TargetID:   u.ID.String(),
			IPAddress:  ip,
			Outcome:    "success",
		}); err != nil {
			slog.Error("audit write failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if err := h.userStore.SetLastLoginAt(r.Context(), tx, u.ID); err != nil {
			slog.Error("login: SetLastLoginAt failed (no-mfa branch)", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			slog.Error("login: commit failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		sessionToken, err := h.sessionStore.Create(r.Context(), u.ID.String(), ip, r.Header.Get("User-Agent"))
		if err != nil {
			slog.Error("login: session.Create failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		session.SetCookie(w, sessionToken, h.cookieSecure)
		resp := map[string]any{"user": userDTO(u)}
		if sanitizedReturnTo != "" {
			resp["redirect_to"] = sanitizedReturnTo
		}
		httputil.WriteJSON(w, http.StatusOK, resp)
	}
}

func (h *Handler) PostLogout(w http.ResponseWriter, r *http.Request) {
	u, ok := CurrentUser(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}

	ip := extractClientIP(r)

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("failed to begin tx", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if auditErr := h.auditStore.Log(r.Context(), tx, audit.Entry{
		EventType:  "logout.completed",
		ActorID:    &u.ID,
		ActorEmail: u.Email,
		TargetType: "user",
		TargetID:   u.ID.String(),
		IPAddress:  ip,
		Outcome:    "success",
	}); auditErr != nil {
		slog.Error("audit write failed", "error", auditErr)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if commitErr := tx.Commit(r.Context()); commitErr != nil {
		slog.Error("commit failed", "error", commitErr)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if cookie, cookieErr := r.Cookie("schlass_session"); cookieErr == nil {
		if delErr := h.sessionStore.Delete(r.Context(), u.ID.String(), cookie.Value); delErr != nil {
			slog.Error("session delete failed", "error", delErr)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
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

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (h *Handler) PostChangePassword(w http.ResponseWriter, r *http.Request) {
	current, ok := CurrentUser(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}

	pendingReturnTo := ""
	if oldCookie, cookieErr := r.Cookie("schlass_session"); cookieErr == nil {
		if sess, err := h.sessionStore.Get(r.Context(), oldCookie.Value); err == nil && sess != nil {
			pendingReturnTo = sess.PendingReturnTo
		}
	}

	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}

	verifyOK, verifyErr := crypto.VerifyPassword(req.CurrentPassword, current.PasswordHash)
	if verifyErr != nil {
		slog.Error("auth.PostChangePassword: verify current password", "error", verifyErr)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if !verifyOK {
		httputil.WriteError(w, http.StatusBadRequest, "WRONG_CURRENT_PASSWORD", "Current password is incorrect.")
		return
	}

	policy, err := h.instanceConfig.PasswordPolicy(r.Context(), h.pool)
	if err != nil {
		slog.Error("auth.PostChangePassword: load password policy", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := validate.Password(req.NewPassword, policy); err != nil {
		var policyErr *apierrors.PasswordPolicyError
		if errors.As(err, &policyErr) {
			httputil.WriteError(w, http.StatusBadRequest, "PASSWORD_POLICY_VIOLATION", err.Error())
			return
		}
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	if pwned, hibpErr := h.hibpChecker.IsPwned(r.Context(), req.NewPassword); hibpErr != nil {
		slog.Warn("password_breach_check: hibp unavailable", "error", hibpErr)
	} else if pwned {
		httputil.WriteError(w, http.StatusBadRequest, "PASSWORD_BREACHED",
			"This password has appeared in a known data breach. Choose a different one.")
		return
	}

	newHash, err := crypto.HashPassword(req.NewPassword)
	if err != nil {
		slog.Error("auth.PostChangePassword: hash new password", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	ip := extractClientIP(r)

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("auth.PostChangePassword: begin tx", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := h.userStore.SetPasswordHash(r.Context(), tx, current.ID, newHash, false); err != nil {
		slog.Error("auth.PostChangePassword: set password hash", "error", err, "user_id", current.ID) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if auditErr := h.auditStore.Log(r.Context(), tx, audit.Entry{
		EventType:  "password.changed",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "user",
		TargetID:   current.ID.String(),
		IPAddress:  ip,
		Outcome:    "success",
	}); auditErr != nil {
		slog.Error("audit password.changed write failed", "error", auditErr)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if auditErr := h.auditStore.Log(r.Context(), tx, audit.Entry{
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("auth.PostChangePassword: commit", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := session.RevokeBeforeSetNow(r.Context(), h.valkey, current.ID.String()); err != nil {
		slog.Error("auth.PostChangePassword: revoke_before Valkey write failed", "error", err, "user_id", current.ID) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
	}

	if oldCookie, cookieErr := r.Cookie("schlass_session"); cookieErr == nil {
		if delErr := h.sessionStore.Delete(r.Context(), current.ID.String(), oldCookie.Value); delErr != nil {
			slog.Warn("auth.PostChangePassword: old session delete degraded", "error", delErr, "user_id", current.ID) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		}
	}

	newToken, err := h.sessionStore.Create(r.Context(), current.ID.String(), ip, r.Header.Get("User-Agent"))
	if err != nil {
		slog.Error("auth.PostChangePassword: session rotate create failed (password was changed)", "error", err, "user_id", current.ID) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "schlass_session",
		Value:    newToken,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	resp := map[string]any{}
	if pendingReturnTo != "" {
		resp["redirect_to"] = pendingReturnTo
	}
	httputil.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) PostDisableMfa(w http.ResponseWriter, r *http.Request) {
	current, ok := CurrentUser(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}

	if current.TOTPEnrolledAt == nil {
		httputil.WriteError(w, http.StatusBadRequest, "MFA_NOT_ENROLLED", "Two-factor authentication is not enabled on this account.")
		return
	}

	full, err := h.userStore.GetByID(r.Context(), h.pool, current.ID)
	if err != nil {
		slog.Error("disable-mfa: GetByID failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	ok2, err := crypto.VerifyPassword(req.CurrentPassword, full.PasswordHash)
	if err != nil {
		slog.Error("disable-mfa: VerifyPassword failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if !ok2 {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid password.")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	deleted, err := h.recoveryCodeStore.DeleteAllForUser(r.Context(), tx, current.ID)
	if err != nil {
		slog.Error("disable-mfa: DeleteAllForUser failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.userStore.ClearTOTP(r.Context(), tx, current.ID); err != nil {
		slog.Error("disable-mfa: ClearTOTP failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	wasEnrolledAt := current.TOTPEnrolledAt.Format(time.RFC3339)
	if err := h.auditStore.Log(r.Context(), tx, audit.Entry{
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if auditErr := h.auditStore.Log(r.Context(), tx, audit.Entry{
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("disable-mfa: Commit failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.sessionStore.DeleteAllForUser(r.Context(), current.ID.String()); err != nil {
		slog.Error("disable-mfa: session revocation failed", "error", err, "user_id", current.ID)
	}
	if err := session.RevokeBeforeSetNow(r.Context(), h.valkey, current.ID.String()); err != nil {
		slog.Error("disable-mfa: revoke_before Valkey write failed", "error", err, "user_id", current.ID) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "schlass_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.cookieSecure,
		MaxAge:   -1,
	})

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"disabled": true})
}

func (h *Handler) GetMe(w http.ResponseWriter, r *http.Request) {
	u, ok := CurrentUser(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}

	mfaRequired, err := h.configStore.GetBool(r.Context(), h.pool, "mfa_required")
	if err != nil {
		slog.Error("GetMe: mfa_required read failed", "error", err)
		mfaRequired = true
	}
	forceMFAEnrollment := mfaRequired && u.TOTPEnrolledAt == nil

	dto := userDTO(u)
	dto["force_mfa_enrollment"] = forceMFAEnrollment

	if u.TOTPEnrolledAt != nil {
		count, err := h.recoveryCodeStore.CountUnused(r.Context(), h.pool, u.ID)
		if err != nil {
			slog.Error("GetMe: CountUnused recovery codes failed", "error", err)
		} else {
			dto["mfa"] = map[string]any{"unused_recovery_codes": count}
		}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"user": dto})
}
