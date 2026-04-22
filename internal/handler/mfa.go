package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/abdo75/Schlass/internal/config"
	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/store"
)

// MfaHandler serves /api/mfa/enrollment/* and /api/mfa/challenge. Enrollment
// and challenge state live in Valkey keyed by short-lived cookies; /complete
// commits the encrypted secret + recovery-code hashes to PG in one tx.
type MfaHandler struct {
	pool              *pgxpool.Pool
	valkey            *redis.Client
	userStore         *store.UserStore
	recoveryCodeStore *store.RecoveryCodeStore
	auditStore        AuditLogger
	sessionStore      session.Store
	instanceConfig    *config.InstanceConfig
	configStore       *store.ConfigStore
	encryptionKey     []byte
	secureCookie      bool
}

func NewMfaHandler(
	pool *pgxpool.Pool,
	valkey *redis.Client,
	userStore *store.UserStore,
	recoveryCodeStore *store.RecoveryCodeStore,
	auditStore AuditLogger,
	sessionStore session.Store,
	instanceConfig *config.InstanceConfig,
	configStore *store.ConfigStore,
	encryptionKey []byte,
	publicURL string,
) *MfaHandler {
	return &MfaHandler{
		pool:              pool,
		valkey:            valkey,
		userStore:         userStore,
		recoveryCodeStore: recoveryCodeStore,
		auditStore:        auditStore,
		sessionStore:      sessionStore,
		instanceConfig:    instanceConfig,
		configStore:       configStore,
		encryptionKey:     encryptionKey,
		secureCookie:      isSecureURL(publicURL),
	}
}

const (
	MfaEnrollCookieName    = "schlass_mfa_enroll"
	MfaChallengeCookieName = "schlass_mfa_challenge"
)

const (
	mfaEnrollTTL    = 10 * time.Minute
	mfaChallengeTTL = 120 * time.Second //nolint:unused // used by Task 12 (PostLogin integration)
)

const (
	mfaEnrollVerifyMaxAttempts = 5
	mfaChallengeMaxAttempts    = 5
)

const (
	mfaEnrollKeyPrefix    = "mfa:enroll:"
	mfaChallengeKeyPrefix = "mfa:challenge:"
)

// mfaEnrollContext captures who's enrolling and which auth mode they
// arrived via. Cookie path = pre-session (first login or post-admin-reset);
// session path = post-session (setup-wizard admin, or a user admin-reset
// while holding an active session).
type mfaEnrollContext struct {
	UserID        uuid.UUID
	Email         string
	SessionAuthed bool
	EnrollToken   string
}

var (
	errNoEnrollAuth    = errors.New("no enrollment authorization")
	errAlreadyEnrolled = errors.New("already enrolled")
)

// resolveEnrollPrincipal prefers the enrollment cookie; falls back to a
// session cookie only when the user genuinely needs enrollment
// (mfa_required=true AND totp_enrolled_at IS NULL). Without this dual-auth
// the setup-wizard admin gets stuck in an infinite /setup-mfa ↔ /admin loop.
func (h *MfaHandler) resolveEnrollPrincipal(r *http.Request) (*mfaEnrollContext, error) {
	if tokenCookie, err := r.Cookie(MfaEnrollCookieName); err == nil && tokenCookie.Value != "" {
		token := tokenCookie.Value
		key := mfaEnrollKeyPrefix + token
		userIDStr, err := h.valkey.HGet(r.Context(), key, "user_id").Result()
		if err == nil && userIDStr != "" {
			uid, perr := uuid.Parse(userIDStr)
			if perr == nil {
				u, uerr := h.userStore.GetByID(r.Context(), h.pool, uid)
				if uerr == nil {
					return &mfaEnrollContext{
						UserID:        uid,
						Email:         u.Email,
						SessionAuthed: false,
						EnrollToken:   token,
					}, nil
				}
			}
		}
	}

	sessionCookie, err := r.Cookie("schlass_session")
	if err != nil || sessionCookie.Value == "" {
		return nil, errNoEnrollAuth
	}
	sess, err := h.sessionStore.Get(r.Context(), sessionCookie.Value)
	if err != nil || sess == nil {
		return nil, errNoEnrollAuth
	}
	uid, err := uuid.Parse(sess.UserID)
	if err != nil {
		return nil, errNoEnrollAuth
	}
	user, err := h.userStore.GetByID(r.Context(), h.pool, uid)
	if err != nil {
		return nil, errNoEnrollAuth
	}
	mfaRequired, err := h.configStore.GetBool(r.Context(), h.pool, "mfa_required")
	if err != nil {
		return nil, errNoEnrollAuth
	}
	if !mfaRequired || user.TOTPEnrolledAt != nil {
		return nil, errAlreadyEnrolled
	}
	return &mfaEnrollContext{
		UserID:        uid,
		Email:         user.Email,
		SessionAuthed: true,
	}, nil
}

func (h *MfaHandler) PostEnrollmentStart(w http.ResponseWriter, r *http.Request) {
	ctx, err := h.resolveEnrollPrincipal(r)
	if err != nil {
		if errors.Is(err, errAlreadyEnrolled) {
			writeError(w, http.StatusBadRequest, "MFA_ALREADY_ENROLLED", "This account already has two-factor authentication enabled.")
		} else {
			writeError(w, http.StatusUnauthorized, "MFA_ENROLLMENT_EXPIRED", "Enrollment session has expired.")
		}
		return
	}

	var key string
	if ctx.SessionAuthed {
		token, err := generateRandomToken(32)
		if err != nil {
			slog.Error("mfa enroll: generateRandomToken failed", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		key = mfaEnrollKeyPrefix + token
		if err := h.valkey.HSet(r.Context(), key, "user_id", ctx.UserID.String()).Err(); err != nil {
			slog.Error("mfa enroll: HSet user_id (session-authed) failed", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if err := h.valkey.Expire(r.Context(), key, mfaEnrollTTL).Err(); err != nil {
			slog.Error("mfa enroll: Expire (session-authed) failed", "error", err)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     MfaEnrollCookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   h.secureCookie,
			MaxAge:   int(mfaEnrollTTL.Seconds()),
		})
		// session_authed flag tells /complete to skip creating a new session.
		if err := h.valkey.HSet(r.Context(), key, "session_authed", "1").Err(); err != nil {
			slog.Error("mfa enroll: HSet session_authed failed", "error", err)
		}
	} else {
		key = mfaEnrollKeyPrefix + ctx.EnrollToken
	}

	user, err := h.userStore.GetByID(r.Context(), h.pool, ctx.UserID)
	if err != nil {
		slog.Error("mfa enroll: GetByID failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if user.TOTPEnrolledAt != nil {
		writeError(w, http.StatusBadRequest, "MFA_ALREADY_ENROLLED", "This account already has two-factor authentication enabled.")
		return
	}

	// Any pre-existing secret on this token (user refreshed mid-flow) is
	// overwritten; the new call is authoritative.
	secret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		slog.Error("mfa enroll: GenerateTOTPSecret failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.valkey.HSet(r.Context(), key, "secret_base32", secret).Err(); err != nil {
		slog.Error("mfa enroll: HSet secret failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.valkey.Expire(r.Context(), key, mfaEnrollTTL).Err(); err != nil {
		slog.Error("mfa enroll: Expire refresh failed", "error", err)
	}

	issuer, err := h.instanceConfig.InstanceName(r.Context(), h.pool)
	if err != nil {
		slog.Warn("mfa enroll: failed to read instance_name; falling back to Schlass", "error", err)
		issuer = ""
	}
	if issuer == "" {
		issuer = "Schlass"
	}

	uri, err := crypto.BuildProvisionURI(issuer, ctx.Email, secret)
	if err != nil {
		slog.Error("mfa enroll: BuildProvisionURI failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"secret_base32": secret,
		"provision_uri": uri,
	})
}

func (h *MfaHandler) PostEnrollmentVerify(w http.ResponseWriter, r *http.Request) {
	tokenCookie, err := r.Cookie(MfaEnrollCookieName)
	if err != nil || tokenCookie.Value == "" {
		writeError(w, http.StatusUnauthorized, "MFA_ENROLLMENT_EXPIRED", "Enrollment session has expired.")
		return
	}
	token := tokenCookie.Value
	key := mfaEnrollKeyPrefix + token

	// Atomic HIncrBy — increment before any verification work so concurrent
	// requests cannot race on the counter.
	attempts, err := h.valkey.HIncrBy(r.Context(), key, "verify_attempts", 1).Result()
	if err != nil {
		slog.Error("mfa enroll verify: HIncrBy failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if attempts > mfaEnrollVerifyMaxAttempts {
		h.valkey.Del(r.Context(), key)
		writeError(w, http.StatusUnauthorized, "MFA_ENROLLMENT_EXPIRED", "Too many failed verification attempts — please start again.")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if len(req.Code) != 6 {
		writeError(w, http.StatusUnauthorized, "MFA_INVALID_CODE", "Invalid code.")
		return
	}

	secret, err := h.valkey.HGet(r.Context(), key, "secret_base32").Result()
	if err != nil || secret == "" {
		writeError(w, http.StatusUnauthorized, "MFA_ENROLLMENT_EXPIRED", "Enrollment session has expired — please start again.")
		return
	}

	matched, _, err := crypto.ValidateTOTP(req.Code, secret, 0)
	if err != nil {
		slog.Error("mfa enroll verify: ValidateTOTP failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if !matched {
		writeError(w, http.StatusUnauthorized, "MFA_INVALID_CODE", "Invalid code.")
		return
	}

	plaintext, hashes, err := crypto.GenerateRecoveryCodes()
	if err != nil {
		slog.Error("mfa enroll verify: GenerateRecoveryCodes failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	hashesJSON, err := json.Marshal(hashes)
	if err != nil {
		slog.Error("mfa enroll verify: marshal hashes failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.valkey.HSet(r.Context(), key, "recovery_hashes", hashesJSON).Err(); err != nil {
		slog.Error("mfa enroll verify: HSet recovery_hashes failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"recovery_codes": plaintext,
	})
}

func (h *MfaHandler) PostEnrollmentComplete(w http.ResponseWriter, r *http.Request) {
	tokenCookie, err := r.Cookie(MfaEnrollCookieName)
	if err != nil || tokenCookie.Value == "" {
		writeError(w, http.StatusUnauthorized, "MFA_ENROLLMENT_EXPIRED", "Enrollment session has expired.")
		return
	}
	token := tokenCookie.Value
	key := mfaEnrollKeyPrefix + token

	var req struct {
		Acknowledged bool `json:"acknowledged"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if !req.Acknowledged {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "You must acknowledge the recovery codes.")
		return
	}

	state, err := h.valkey.HGetAll(r.Context(), key).Result()
	if err != nil || len(state) == 0 {
		writeError(w, http.StatusUnauthorized, "MFA_ENROLLMENT_EXPIRED", "Enrollment session has expired — please start again.")
		return
	}
	userIDStr := state["user_id"]
	secret := state["secret_base32"]
	hashesJSON := state["recovery_hashes"]
	if userIDStr == "" || secret == "" || hashesJSON == "" {
		writeError(w, http.StatusBadRequest, "MFA_ENROLLMENT_EXPIRED", "Enrollment is not in a state to complete — please verify a code first.")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		slog.Error("mfa complete: malformed user_id in valkey")
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	var hashStrings []string
	if err := json.Unmarshal([]byte(hashesJSON), &hashStrings); err != nil {
		slog.Error("mfa complete: unmarshal hashes failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if len(hashStrings) != 10 {
		slog.Error("mfa complete: wrong number of recovery hashes", "count", len(hashStrings))
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	hashes := make([][]byte, len(hashStrings))
	for i, s := range hashStrings {
		hashes[i] = []byte(s)
	}

	encrypted, err := crypto.Encrypt([]byte(secret), h.encryptionKey, totpSecretAAD(userID.String()))
	if err != nil {
		slog.Error("mfa complete: Encrypt failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// session-authed path skips last_login_at stamp below — that user
	// already had it set when the original session was issued.
	sessionAuthed := state["session_authed"] == "1"

	// return_to is only set on the cookie-path (threaded from /api/login).
	returnTo := state["return_to"]

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("mfa complete: Begin failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := h.userStore.SetTOTPEnrolled(r.Context(), tx, userID, encrypted); err != nil {
		slog.Error("mfa complete: SetTOTPEnrolled failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.recoveryCodeStore.Insert(r.Context(), tx, userID, hashes); err != nil {
		slog.Error("mfa complete: Insert recovery codes failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	user, err := h.userStore.GetByID(r.Context(), tx, userID)
	if err != nil {
		slog.Error("mfa complete: GetByID failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	ip := extractClientIP(r)
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "mfa.enrollment_completed",
		ActorID:    &userID,
		ActorEmail: user.Email,
		TargetType: "user",
		TargetID:   userID.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"method": "totp"},
	}); err != nil {
		slog.Error("mfa complete: audit write failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if !sessionAuthed {
		if err := h.userStore.SetLastLoginAt(r.Context(), tx, userID); err != nil {
			slog.Error("mfa complete: SetLastLoginAt failed", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("mfa complete: Commit failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	h.valkey.Del(r.Context(), key)
	http.SetCookie(w, &http.Cookie{
		Name:     MfaEnrollCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   h.secureCookie,
		MaxAge:   -1,
	})

	if !sessionAuthed {
		sessionToken, err := h.sessionStore.Create(r.Context(), userID.String(), ip, r.Header.Get("User-Agent"))
		if err != nil {
			slog.Error("mfa complete: session.Create failed", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		setSessionCookie(w, sessionToken, h.secureCookie)
	}

	resp := map[string]any{"user": userDTO(user)}
	if returnTo != "" {
		resp["redirect_to"] = returnTo
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *MfaHandler) PostChallenge(w http.ResponseWriter, r *http.Request) {
	tokenCookie, err := r.Cookie(MfaChallengeCookieName)
	if err != nil || tokenCookie.Value == "" {
		writeError(w, http.StatusUnauthorized, "MFA_CHALLENGE_EXPIRED", "Sign-in session expired — please sign in again.")
		return
	}
	token := tokenCookie.Value
	key := mfaChallengeKeyPrefix + token

	var req struct {
		Code         string `json:"code"`
		RecoveryCode string `json:"recovery_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}

	// Decrement-before-verify: concurrent requests cannot slip through by
	// racing on the counter.
	remaining, err := h.valkey.HIncrBy(r.Context(), key, "attempts_remaining", -1).Result()
	if err != nil {
		writeError(w, http.StatusUnauthorized, "MFA_CHALLENGE_EXPIRED", "Sign-in session expired — please sign in again.")
		return
	}
	if remaining < 0 {
		h.valkey.Del(r.Context(), key)
		h.writeChallengeFailedAudit(r, "", "max_attempts")
		writeError(w, http.StatusUnauthorized, "MFA_CHALLENGE_MAX_ATTEMPTS", "Too many failed attempts — please sign in again.")
		return
	}

	userIDStr, err := h.valkey.HGet(r.Context(), key, "user_id").Result()
	if err != nil || userIDStr == "" {
		writeError(w, http.StatusUnauthorized, "MFA_CHALLENGE_EXPIRED", "Sign-in session expired — please sign in again.")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// redis.Nil on an absent field is benign; only genuine transport errors
	// are worth logging.
	returnTo, err := h.valkey.HGet(r.Context(), key, "return_to").Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		slog.Warn("mfa challenge: return_to HGet degraded", "error", err)
		returnTo = ""
	}

	user, err := h.userStore.GetByID(r.Context(), h.pool, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if req.RecoveryCode != "" {
		h.verifyRecoveryCode(w, r, user, req.RecoveryCode, token, key, returnTo)
		return
	}
	if len(req.Code) != 6 {
		if remaining == 0 {
			h.valkey.Del(r.Context(), key)
		}
		h.writeChallengeFailedAudit(r, userID.String(), "invalid_code")
		writeError(w, http.StatusUnauthorized, "MFA_INVALID_CODE", "Invalid code.")
		return
	}

	secret, err := crypto.Decrypt(user.TOTPSecretEncrypted, h.encryptionKey, totpSecretAAD(user.ID.String()))
	if err != nil {
		slog.Error("mfa challenge: Decrypt failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	matched, step, err := crypto.ValidateTOTP(req.Code, string(secret), user.LastUsedTOTPCounter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if !matched {
		if remaining == 0 {
			h.valkey.Del(r.Context(), key)
		}
		h.writeChallengeFailedAudit(r, userID.String(), "invalid_code")
		writeError(w, http.StatusUnauthorized, "MFA_INVALID_CODE", "Invalid code.")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := h.userStore.AdvanceTOTPCounter(r.Context(), tx, userID, step); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	ip := extractClientIP(r)
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "login.succeeded",
		ActorID:    &userID,
		ActorEmail: user.Email,
		TargetType: "user",
		TargetID:   userID.String(),
		IPAddress:  ip,
		Outcome:    "success",
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "mfa.challenge_succeeded",
		ActorID:    &userID,
		ActorEmail: user.Email,
		TargetType: "user",
		TargetID:   userID.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"method": "totp"},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.userStore.SetLastLoginAt(r.Context(), tx, userID); err != nil {
		slog.Error("mfa challenge: SetLastLoginAt failed (totp)", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	h.valkey.Del(r.Context(), key)
	http.SetCookie(w, &http.Cookie{
		Name:     MfaChallengeCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   h.secureCookie,
		MaxAge:   -1,
	})

	sessionToken, err := h.sessionStore.Create(r.Context(), userID.String(), ip, r.Header.Get("User-Agent"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	setSessionCookie(w, sessionToken, h.secureCookie)
	resp := map[string]any{"user": userDTO(user)}
	if returnTo != "" {
		resp["redirect_to"] = returnTo
	}
	writeJSON(w, http.StatusOK, resp)
}

// writeChallengeFailedAudit is best-effort (own tx; logs on failure but
// does not block the caller). Documented exception to audit-in-tx: the
// brute-force guard is the atomic decrement, not the audit row.
func (h *MfaHandler) writeChallengeFailedAudit(r *http.Request, userID, reason string) {
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("mfa challenge: audit tx begin failed", "error", err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	var actorID *uuid.UUID
	actorEmail := ""
	if userID != "" {
		if u, err := uuid.Parse(userID); err == nil {
			actorID = &u
			if user, err := h.userStore.GetByID(r.Context(), tx, u); err == nil {
				actorEmail = user.Email
			}
		}
	}
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "mfa.challenge_failed",
		ActorID:    actorID,
		ActorEmail: actorEmail,
		TargetType: "user",
		TargetID:   userID,
		IPAddress:  extractClientIP(r),
		Outcome:    "failure",
		Metadata:   map[string]any{"reason": reason},
	}); err != nil {
		slog.Error("mfa challenge: audit write failed", "error", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("mfa challenge: audit tx commit failed", "error", err)
	}
}

// verifyRecoveryCode iterates ALL unused recovery codes in constant time
// (no short-circuit on first match) — variable-time-with-mismatch leaks the
// count of remaining codes via repeated-failure timing. ~100ms per attempt
// is an accepted cost.
func (h *MfaHandler) verifyRecoveryCode(w http.ResponseWriter, r *http.Request, user *store.User, plaintext, token, key, returnTo string) {
	codes, err := h.recoveryCodeStore.ListUnused(r.Context(), h.pool, user.ID)
	if err != nil {
		slog.Error("mfa challenge: ListUnused failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	var matchedID *uuid.UUID
	for _, c := range codes {
		ok, err := crypto.VerifyPassword(plaintext, string(c.CodeHash))
		if err != nil {
			slog.Error("mfa challenge: VerifyPassword failed", "error", err)
			continue
		}
		if ok && matchedID == nil {
			id := c.ID
			matchedID = &id
		}
		// Continue iterating — timing must be uniform after first match.
	}

	if matchedID == nil {
		h.writeChallengeFailedAudit(r, user.ID.String(), "invalid_recovery_code")
		writeError(w, http.StatusUnauthorized, "MFA_INVALID_RECOVERY_CODE", "Invalid recovery code.")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := h.recoveryCodeStore.MarkUsed(r.Context(), tx, *matchedID); err != nil {
		slog.Error("mfa challenge: MarkUsed failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	ip := extractClientIP(r)
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "login.succeeded",
		ActorID:    &user.ID,
		ActorEmail: user.Email,
		TargetType: "user",
		TargetID:   user.ID.String(),
		IPAddress:  ip,
		Outcome:    "success",
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "mfa.challenge_succeeded",
		ActorID:    &user.ID,
		ActorEmail: user.Email,
		TargetType: "user",
		TargetID:   user.ID.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"method": "recovery_code"},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "mfa.recovery_code_used",
		ActorID:    &user.ID,
		ActorEmail: user.Email,
		TargetType: "user",
		TargetID:   user.ID.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"code_id": matchedID.String()},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.userStore.SetLastLoginAt(r.Context(), tx, user.ID); err != nil {
		slog.Error("mfa challenge: SetLastLoginAt failed (recovery)", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	h.valkey.Del(r.Context(), key)
	http.SetCookie(w, &http.Cookie{
		Name:     MfaChallengeCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   h.secureCookie,
		MaxAge:   -1,
	})
	sessionToken, err := h.sessionStore.Create(r.Context(), user.ID.String(), ip, r.Header.Get("User-Agent"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	setSessionCookie(w, sessionToken, h.secureCookie)
	resp := map[string]any{"user": userDTO(user)}
	if returnTo != "" {
		resp["redirect_to"] = returnTo
	}
	writeJSON(w, http.StatusOK, resp)
}

// totpSecretAAD binds encrypted TOTP secrets to the owning user so a blob
// swapped between user rows at the DB layer fails decryption.
func totpSecretAAD(userID string) []byte {
	return []byte("user_totp_secret:" + userID)
}
