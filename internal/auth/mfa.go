package auth

// TOTP enrollment, challenge verification, and recovery code management.
// Transient enrollment/challenge state lives in Valkey; committed state
// (encrypted secret, recovery hashes) is written to PG.

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/httputil"
	"github.com/abdo75/Schlass/internal/instanceconfig"
	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/users"
)

// MFAHandler serves /api/mfa/enrollment/* and /api/mfa/challenge. Enrollment
// and challenge state live in Valkey keyed by short-lived cookies; /complete
// commits the encrypted secret + recovery-code hashes to PG in one tx.
type MFAHandler struct {
	pool              *pgxpool.Pool
	valkey            *redis.Client
	userStore         *users.Store
	recoveryCodeStore *RecoveryCodeStore
	auditStore        audit.Logger
	sessionStore      session.Store
	instanceConfig    *instanceconfig.Service
	configStore       *instanceconfig.Store
	encryptionKey     []byte
	secureCookie      bool
}

func NewMFAHandler(
	pool *pgxpool.Pool,
	valkey *redis.Client,
	userStore *users.Store,
	recoveryCodeStore *RecoveryCodeStore,
	auditStore audit.Logger,
	sessionStore session.Store,
	instanceConfig *instanceconfig.Service,
	configStore *instanceconfig.Store,
	encryptionKey []byte,
	publicURL string,
) *MFAHandler {
	return &MFAHandler{
		pool:              pool,
		valkey:            valkey,
		userStore:         userStore,
		recoveryCodeStore: recoveryCodeStore,
		auditStore:        auditStore,
		sessionStore:      sessionStore,
		instanceConfig:    instanceConfig,
		configStore:       configStore,
		encryptionKey:     encryptionKey,
		secureCookie:      session.IsSecureURL(publicURL),
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
func (h *MFAHandler) resolveEnrollPrincipal(r *http.Request) (*mfaEnrollContext, error) {
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
	u, err := h.userStore.GetByID(r.Context(), h.pool, uid)
	if err != nil {
		return nil, errNoEnrollAuth
	}
	mfaRequired, err := h.configStore.GetBool(r.Context(), h.pool, "mfa_required")
	if err != nil {
		return nil, errNoEnrollAuth
	}
	if !mfaRequired || u.TOTPEnrolledAt != nil {
		return nil, errAlreadyEnrolled
	}
	return &mfaEnrollContext{
		UserID:        uid,
		Email:         u.Email,
		SessionAuthed: true,
	}, nil
}

func (h *MFAHandler) PostEnrollmentStart(w http.ResponseWriter, r *http.Request) {
	ctx, err := h.resolveEnrollPrincipal(r)
	if err != nil {
		if errors.Is(err, errAlreadyEnrolled) {
			httputil.WriteError(w, http.StatusBadRequest, "MFA_ALREADY_ENROLLED", "This account already has two-factor authentication enabled.")
		} else {
			httputil.WriteError(w, http.StatusUnauthorized, "MFA_ENROLLMENT_EXPIRED", "Enrollment session has expired.")
		}
		return
	}

	var key string
	if ctx.SessionAuthed {
		token, err := crypto.RandomToken(32)
		if err != nil {
			slog.Error("mfa enroll: generateRandomToken failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		key = mfaEnrollKeyPrefix + token
		if err := h.valkey.HSet(r.Context(), key, "user_id", ctx.UserID.String()).Err(); err != nil {
			slog.Error("mfa enroll: HSet user_id (session-authed) failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
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

	u, err := h.userStore.GetByID(r.Context(), h.pool, ctx.UserID)
	if err != nil {
		slog.Error("mfa enroll: GetByID failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if u.TOTPEnrolledAt != nil {
		httputil.WriteError(w, http.StatusBadRequest, "MFA_ALREADY_ENROLLED", "This account already has two-factor authentication enabled.")
		return
	}

	// Any pre-existing secret on this token (user refreshed mid-flow) is
	// overwritten; the new call is authoritative.
	secret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		slog.Error("mfa enroll: GenerateTOTPSecret failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.valkey.HSet(r.Context(), key, "secret_base32", secret).Err(); err != nil {
		slog.Error("mfa enroll: HSet secret failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"secret_base32": secret,
		"provision_uri": uri,
	})
}

func (h *MFAHandler) PostEnrollmentVerify(w http.ResponseWriter, r *http.Request) {
	tokenCookie, err := r.Cookie(MfaEnrollCookieName)
	if err != nil || tokenCookie.Value == "" {
		httputil.WriteError(w, http.StatusUnauthorized, "MFA_ENROLLMENT_EXPIRED", "Enrollment session has expired.")
		return
	}
	token := tokenCookie.Value
	key := mfaEnrollKeyPrefix + token

	// Atomic HIncrBy — increment before any verification work so concurrent
	// requests cannot race on the counter.
	attempts, err := h.valkey.HIncrBy(r.Context(), key, "verify_attempts", 1).Result()
	if err != nil {
		slog.Error("mfa enroll verify: HIncrBy failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if attempts > mfaEnrollVerifyMaxAttempts {
		h.valkey.Del(r.Context(), key)
		httputil.WriteError(w, http.StatusUnauthorized, "MFA_ENROLLMENT_EXPIRED", "Too many failed verification attempts — please start again.")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if len(req.Code) != 6 {
		httputil.WriteError(w, http.StatusUnauthorized, "MFA_INVALID_CODE", "Invalid code.")
		return
	}

	secret, err := h.valkey.HGet(r.Context(), key, "secret_base32").Result()
	if err != nil || secret == "" {
		httputil.WriteError(w, http.StatusUnauthorized, "MFA_ENROLLMENT_EXPIRED", "Enrollment session has expired — please start again.")
		return
	}

	matched, _, err := crypto.ValidateTOTP(req.Code, secret, 0)
	if err != nil {
		slog.Error("mfa enroll verify: ValidateTOTP failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if !matched {
		httputil.WriteError(w, http.StatusUnauthorized, "MFA_INVALID_CODE", "Invalid code.")
		return
	}

	plaintext, hashes, err := crypto.GenerateRecoveryCodes()
	if err != nil {
		slog.Error("mfa enroll verify: GenerateRecoveryCodes failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	hashesJSON, err := json.Marshal(hashes)
	if err != nil {
		slog.Error("mfa enroll verify: marshal hashes failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.valkey.HSet(r.Context(), key, "recovery_hashes", hashesJSON).Err(); err != nil {
		slog.Error("mfa enroll verify: HSet recovery_hashes failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"recovery_codes": plaintext,
	})
}

func (h *MFAHandler) PostEnrollmentComplete(w http.ResponseWriter, r *http.Request) {
	tokenCookie, err := r.Cookie(MfaEnrollCookieName)
	if err != nil || tokenCookie.Value == "" {
		httputil.WriteError(w, http.StatusUnauthorized, "MFA_ENROLLMENT_EXPIRED", "Enrollment session has expired.")
		return
	}
	token := tokenCookie.Value
	key := mfaEnrollKeyPrefix + token

	var req struct {
		Acknowledged bool `json:"acknowledged"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if !req.Acknowledged {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "You must acknowledge the recovery codes.")
		return
	}

	state, err := h.valkey.HGetAll(r.Context(), key).Result()
	if err != nil || len(state) == 0 {
		httputil.WriteError(w, http.StatusUnauthorized, "MFA_ENROLLMENT_EXPIRED", "Enrollment session has expired — please start again.")
		return
	}
	userIDStr := state["user_id"]
	secret := state["secret_base32"]
	hashesJSON := state["recovery_hashes"]
	if userIDStr == "" || secret == "" || hashesJSON == "" {
		httputil.WriteError(w, http.StatusBadRequest, "MFA_ENROLLMENT_EXPIRED", "Enrollment is not in a state to complete — please verify a code first.")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		slog.Error("mfa complete: malformed user_id in valkey")
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	var hashStrings []string
	if err := json.Unmarshal([]byte(hashesJSON), &hashStrings); err != nil {
		slog.Error("mfa complete: unmarshal hashes failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if len(hashStrings) != 10 {
		slog.Error("mfa complete: wrong number of recovery hashes", "count", len(hashStrings))
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	hashes := make([][]byte, len(hashStrings))
	for i, s := range hashStrings {
		hashes[i] = []byte(s)
	}

	encrypted, err := crypto.Encrypt([]byte(secret), h.encryptionKey, totpSecretAAD(userID.String()))
	if err != nil {
		slog.Error("mfa complete: Encrypt failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := h.userStore.SetTOTPEnrolled(r.Context(), tx, userID, encrypted); err != nil {
		slog.Error("mfa complete: SetTOTPEnrolled failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.recoveryCodeStore.Insert(r.Context(), tx, userID, hashes); err != nil {
		slog.Error("mfa complete: Insert recovery codes failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	u, err := h.userStore.GetByID(r.Context(), tx, userID)
	if err != nil {
		slog.Error("mfa complete: GetByID failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	ip := extractClientIP(r)
	if err := h.auditStore.Emit(r.Context(), tx, audit.Event{
		EventType:  "mfa.enrollment_completed",
		ActorID:    &userID,
		ActorEmail: u.Email,
		TargetType: "user",
		TargetID:   userID.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"method": "totp"},
	}); err != nil {
		slog.Error("mfa complete: audit write failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if !sessionAuthed {
		// Cookie-path enrollment is the second factor of a fresh login (the
		// password was verified before /api/login redirected here). Per
		// NIST 800-53 AU-2 + PCI 10.2.1.1, that successful authentication
		// must produce a login.succeeded record. The session-authed branch
		// (admin enrolling MFA from an already-active session) skips it.
		if err := h.auditStore.Emit(r.Context(), tx, audit.Event{
			EventType:  "login.succeeded",
			ActorID:    &userID,
			ActorEmail: u.Email,
			TargetType: "user",
			TargetID:   userID.String(),
			IPAddress:  ip,
			Outcome:    "success",
			Metadata:   map[string]any{"second_factor": "totp_enrollment"},
		}); err != nil {
			slog.Error("mfa complete: audit login.succeeded failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if err := h.userStore.SetLastLoginAt(r.Context(), tx, userID); err != nil {
			slog.Error("mfa complete: SetLastLoginAt failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("mfa complete: Commit failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
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
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if err := h.sessionStore.MarkMFAVerified(r.Context(), sessionToken); err != nil {
			slog.Error("mfa complete: MarkMFAVerified failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		session.SetCookie(w, sessionToken, h.secureCookie)
	} else if sessionCookie, err := r.Cookie("schlass_session"); err == nil && sessionCookie.Value != "" {
		if err := h.sessionStore.MarkMFAVerified(r.Context(), sessionCookie.Value); err != nil {
			slog.Warn("mfa complete: MarkMFAVerified session-authed failed", "error", err)
		}
	}

	resp := map[string]any{"user": userDTO(u)}
	if returnTo != "" {
		resp["redirect_to"] = returnTo
	}
	httputil.WriteJSON(w, http.StatusOK, resp)
}

func (h *MFAHandler) PostChallenge(w http.ResponseWriter, r *http.Request) {
	tokenCookie, err := r.Cookie(MfaChallengeCookieName)
	if err != nil || tokenCookie.Value == "" {
		httputil.WriteError(w, http.StatusUnauthorized, "MFA_CHALLENGE_EXPIRED", "Sign-in session expired — please sign in again.")
		return
	}
	token := tokenCookie.Value
	key := mfaChallengeKeyPrefix + token

	var req struct {
		Code         string `json:"code"`
		RecoveryCode string `json:"recovery_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}

	// Decrement-before-verify: concurrent requests cannot slip through by
	// racing on the counter.
	remaining, err := h.valkey.HIncrBy(r.Context(), key, "attempts_remaining", -1).Result()
	if err != nil {
		httputil.WriteError(w, http.StatusUnauthorized, "MFA_CHALLENGE_EXPIRED", "Sign-in session expired — please sign in again.")
		return
	}
	if remaining < 0 {
		h.valkey.Del(r.Context(), key)
		h.writeChallengeFailedAudit(r, "", "max_attempts")
		httputil.WriteError(w, http.StatusUnauthorized, "MFA_CHALLENGE_MAX_ATTEMPTS", "Too many failed attempts — please sign in again.")
		return
	}

	userIDStr, err := h.valkey.HGet(r.Context(), key, "user_id").Result()
	if err != nil || userIDStr == "" {
		httputil.WriteError(w, http.StatusUnauthorized, "MFA_CHALLENGE_EXPIRED", "Sign-in session expired — please sign in again.")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// redis.Nil on an absent field is benign; only genuine transport errors
	// are worth logging.
	returnTo, err := h.valkey.HGet(r.Context(), key, "return_to").Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		slog.Warn("mfa challenge: return_to HGet degraded", "error", err)
		returnTo = ""
	}

	u, err := h.userStore.GetByID(r.Context(), h.pool, userID)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if req.RecoveryCode != "" {
		h.verifyRecoveryCode(w, r, u, req.RecoveryCode, token, key, returnTo)
		return
	}
	if len(req.Code) != 6 {
		if remaining == 0 {
			h.valkey.Del(r.Context(), key)
		}
		h.writeChallengeFailedAudit(r, userID.String(), "invalid_code")
		httputil.WriteError(w, http.StatusUnauthorized, "MFA_INVALID_CODE", "Invalid code.")
		return
	}

	secret, err := crypto.Decrypt(u.TOTPSecretEncrypted, h.encryptionKey, totpSecretAAD(u.ID.String()))
	if err != nil {
		slog.Error("mfa challenge: Decrypt failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	matched, step, err := crypto.ValidateTOTP(req.Code, string(secret), u.LastUsedTOTPCounter)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if !matched {
		if remaining == 0 {
			h.valkey.Del(r.Context(), key)
		}
		h.writeChallengeFailedAudit(r, userID.String(), "invalid_code")
		httputil.WriteError(w, http.StatusUnauthorized, "MFA_INVALID_CODE", "Invalid code.")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := h.userStore.AdvanceTOTPCounter(r.Context(), tx, userID, step); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	ip := extractClientIP(r)
	if err := h.auditStore.Emit(r.Context(), tx, audit.Event{
		EventType:  "login.succeeded",
		ActorID:    &userID,
		ActorEmail: u.Email,
		TargetType: "user",
		TargetID:   userID.String(),
		IPAddress:  ip,
		Outcome:    "success",
	}); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.auditStore.Emit(r.Context(), tx, audit.Event{
		EventType:  "mfa.challenge_succeeded",
		ActorID:    &userID,
		ActorEmail: u.Email,
		TargetType: "user",
		TargetID:   userID.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"method": "totp"},
	}); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.userStore.SetLastLoginAt(r.Context(), tx, userID); err != nil {
		slog.Error("mfa challenge: SetLastLoginAt failed (totp)", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.sessionStore.MarkMFAVerified(r.Context(), sessionToken); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	session.SetCookie(w, sessionToken, h.secureCookie)
	resp := map[string]any{"user": userDTO(u)}
	if returnTo != "" {
		resp["redirect_to"] = returnTo
	}
	httputil.WriteJSON(w, http.StatusOK, resp)
}

func (h *MFAHandler) PostStepUpChallenge(w http.ResponseWriter, r *http.Request) {
	user, ok := CurrentUser(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	sessionToken, ok := session.TokenFromContext(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	var req struct {
		Code         string `json:"code"`
		RecoveryCode string `json:"recovery_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if req.RecoveryCode != "" {
		h.verifyStepUpRecoveryCode(w, r, user, req.RecoveryCode, sessionToken)
		return
	}
	if len(req.Code) != 6 || user.TOTPEnrolledAt == nil {
		h.writeStepUpAudit(r, user, "auth.stepup.failed", "failure", "invalid_code")
		httputil.WriteError(w, http.StatusUnauthorized, "MFA_INVALID_CODE", "Invalid code.")
		return
	}
	secret, err := crypto.Decrypt(user.TOTPSecretEncrypted, h.encryptionKey, totpSecretAAD(user.ID.String()))
	if err != nil {
		slog.Error("step-up challenge: Decrypt failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	matched, step, err := crypto.ValidateTOTP(req.Code, string(secret), user.LastUsedTOTPCounter)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if !matched {
		h.writeStepUpAudit(r, user, "auth.stepup.failed", "failure", "invalid_code")
		httputil.WriteError(w, http.StatusUnauthorized, "MFA_INVALID_CODE", "Invalid code.")
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if err := h.userStore.AdvanceTOTPCounter(r.Context(), tx, user.ID, step); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.auditStore.Emit(r.Context(), tx, audit.Event{
		EventType:  "auth.stepup.satisfied",
		ActorID:    &user.ID,
		ActorEmail: user.Email,
		TargetType: "session",
		TargetID:   sessionToken,
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata:   map[string]any{"method": "totp"},
	}); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.sessionStore.MarkMFAVerified(r.Context(), sessionToken); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// writeChallengeFailedAudit is best-effort (own tx; logs on failure but
// does not block the caller). Documented exception to audit-in-tx: the
// brute-force guard is the atomic decrement, not the audit row.
func (h *MFAHandler) writeChallengeFailedAudit(r *http.Request, userID, reason string) {
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("mfa challenge: audit tx begin failed", "error", err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	var actorID *uuid.UUID
	actorEmail := ""
	if userID != "" {
		if uid, err := uuid.Parse(userID); err == nil {
			actorID = &uid
			if u, err := h.userStore.GetByID(r.Context(), tx, uid); err == nil {
				actorEmail = u.Email
			}
		}
	}
	if err := h.auditStore.Emit(r.Context(), tx, audit.Event{
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
func (h *MFAHandler) verifyRecoveryCode(w http.ResponseWriter, r *http.Request, u *users.User, plaintext, token, key, returnTo string) {
	codes, err := h.recoveryCodeStore.ListUnused(r.Context(), h.pool, u.ID)
	if err != nil {
		slog.Error("mfa challenge: ListUnused failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
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
		h.writeChallengeFailedAudit(r, u.ID.String(), "invalid_recovery_code")
		httputil.WriteError(w, http.StatusUnauthorized, "MFA_INVALID_RECOVERY_CODE", "Invalid recovery code.")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := h.recoveryCodeStore.MarkUsed(r.Context(), tx, *matchedID); err != nil {
		slog.Error("mfa challenge: MarkUsed failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	ip := extractClientIP(r)
	if err := h.auditStore.Emit(r.Context(), tx, audit.Event{
		EventType:  "login.succeeded",
		ActorID:    &u.ID,
		ActorEmail: u.Email,
		TargetType: "user",
		TargetID:   u.ID.String(),
		IPAddress:  ip,
		Outcome:    "success",
	}); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.auditStore.Emit(r.Context(), tx, audit.Event{
		EventType:  "mfa.challenge_succeeded",
		ActorID:    &u.ID,
		ActorEmail: u.Email,
		TargetType: "user",
		TargetID:   u.ID.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"method": "recovery_code"},
	}); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.auditStore.Emit(r.Context(), tx, audit.Event{
		EventType:  "mfa.recovery_code_used",
		ActorID:    &u.ID,
		ActorEmail: u.Email,
		TargetType: "user",
		TargetID:   u.ID.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"code_id": matchedID.String()},
	}); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.userStore.SetLastLoginAt(r.Context(), tx, u.ID); err != nil {
		slog.Error("mfa challenge: SetLastLoginAt failed (recovery)", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
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
	sessionToken, err := h.sessionStore.Create(r.Context(), u.ID.String(), ip, r.Header.Get("User-Agent"))
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.sessionStore.MarkMFAVerified(r.Context(), sessionToken); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	session.SetCookie(w, sessionToken, h.secureCookie)
	resp := map[string]any{"user": userDTO(u)}
	if returnTo != "" {
		resp["redirect_to"] = returnTo
	}
	httputil.WriteJSON(w, http.StatusOK, resp)
}

func (h *MFAHandler) verifyStepUpRecoveryCode(w http.ResponseWriter, r *http.Request, u *users.User, plaintext, sessionToken string) {
	codes, err := h.recoveryCodeStore.ListUnused(r.Context(), h.pool, u.ID)
	if err != nil {
		slog.Error("step-up challenge: ListUnused failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	var matchedID *uuid.UUID
	for _, c := range codes {
		ok, err := crypto.VerifyPassword(plaintext, string(c.CodeHash))
		if err != nil {
			slog.Error("step-up challenge: VerifyPassword failed", "error", err)
			continue
		}
		if ok && matchedID == nil {
			id := c.ID
			matchedID = &id
		}
	}
	if matchedID == nil {
		h.writeStepUpAudit(r, u, "auth.stepup.failed", "failure", "invalid_recovery_code")
		httputil.WriteError(w, http.StatusUnauthorized, "MFA_INVALID_RECOVERY_CODE", "Invalid recovery code.")
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if err := h.recoveryCodeStore.MarkUsed(r.Context(), tx, *matchedID); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.auditStore.Emit(r.Context(), tx, audit.Event{
		EventType:  "auth.stepup.satisfied",
		ActorID:    &u.ID,
		ActorEmail: u.Email,
		TargetType: "session",
		TargetID:   sessionToken,
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata:   map[string]any{"method": "recovery_code", "code_id": matchedID.String()},
	}); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.sessionStore.MarkMFAVerified(r.Context(), sessionToken); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *MFAHandler) writeStepUpAudit(r *http.Request, u *users.User, eventType, outcome, reason string) {
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("step-up challenge: audit tx begin failed", "error", err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if err := h.auditStore.Emit(r.Context(), tx, audit.Event{
		EventType:  eventType,
		ActorID:    &u.ID,
		ActorEmail: u.Email,
		TargetType: "session",
		IPAddress:  extractClientIP(r),
		Outcome:    outcome,
		Metadata:   map[string]any{"reason": reason},
	}); err != nil {
		slog.Error("step-up challenge: audit write failed", "error", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("step-up challenge: audit tx commit failed", "error", err)
	}
}

// totpSecretAAD binds encrypted TOTP secrets to the owning user so a blob
// swapped between user rows at the DB layer fails decryption.
func totpSecretAAD(userID string) []byte {
	return []byte("user_totp_secret:" + userID)
}
