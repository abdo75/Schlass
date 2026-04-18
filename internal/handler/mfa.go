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

// MfaHandler serves enrollment (/api/mfa/enrollment/*) and challenge
// (/api/mfa/challenge) endpoints. Enrollment state lives in Valkey keyed by
// the schlass_mfa_enroll cookie until the /complete step commits the
// encrypted secret + recovery-code hashes to PG in a single audit-in-tx
// transaction. Challenge state lives in Valkey keyed by
// schlass_mfa_challenge until verification succeeds or attempts_remaining
// hits zero.
type MfaHandler struct {
	pool              *pgxpool.Pool
	valkey            *redis.Client
	userStore         *store.UserStore
	recoveryCodeStore *store.RecoveryCodeStore
	auditStore        AuditLogger
	sessionStore      session.Store
	configService     *config.ConfigService
	configStore       *store.ConfigStore
	encryptionKey     []byte
	secureCookie      bool // Secure flag on Set-Cookie — true iff SCHLASS_PUBLIC_URL is https
}

// NewMfaHandler constructs the handler with all dependencies. Signature
// mirrors NewAuthHandler's construction-time derivation of secureCookie from
// the public URL.
func NewMfaHandler(
	pool *pgxpool.Pool,
	valkey *redis.Client,
	userStore *store.UserStore,
	recoveryCodeStore *store.RecoveryCodeStore,
	auditStore AuditLogger,
	sessionStore session.Store,
	configService *config.ConfigService,
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
		configService:     configService,
		configStore:       configStore,
		encryptionKey:     encryptionKey,
		secureCookie:      isSecureURL(publicURL),
	}
}

// Cookie names — centralised so the handler, AuthGuard, and any challenge-
// cookie guard all agree on the string.
const (
	MfaEnrollCookieName    = "schlass_mfa_enroll"
	MfaChallengeCookieName = "schlass_mfa_challenge"
)

// Valkey TTLs.
const (
	mfaEnrollTTL    = 10 * time.Minute
	mfaChallengeTTL = 120 * time.Second //nolint:unused // used by Task 12 (PostLogin integration)
)

// Attempt caps for the enrollment-verify and challenge endpoints.
const (
	mfaEnrollVerifyMaxAttempts = 5
	mfaChallengeMaxAttempts    = 5
)

// Valkey key prefixes. Intentionally not the same prefix as the opaque-
// session store (internal/session) to keep MFA transient state visibly
// separate from admin sessions.
const (
	mfaEnrollKeyPrefix    = "mfa:enroll:"
	mfaChallengeKeyPrefix = "mfa:challenge:"
)

// mfaEnrollContext captures who's enrolling and which auth mode they arrived
// via. Enrollment cookie path = pre-session (first login or post-admin-reset
// via fresh login). Session path = post-session (setup wizard admin, or a
// user who got admin-reset while holding an active session).
type mfaEnrollContext struct {
	UserID        uuid.UUID
	Email         string
	SessionAuthed bool   // true = came in via a valid session cookie; false = via enrollment cookie
	EnrollToken   string // empty when SessionAuthed; the raw token when cookie-authed
}

var (
	errNoEnrollAuth    = errors.New("no enrollment authorization")
	errAlreadyEnrolled = errors.New("already enrolled")
)

// resolveEnrollPrincipal returns the enrollment principal from either auth
// source. The enrollment cookie is preferred when present (covers the standard
// login flow). If the cookie is absent or invalid, a session cookie is
// accepted provided the user genuinely needs to enroll
// (mfa_required=true AND totp_enrolled_at IS NULL).
func (h *MfaHandler) resolveEnrollPrincipal(r *http.Request) (*mfaEnrollContext, error) {
	// Prefer enrollment cookie when present.
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
		// Cookie present but Valkey state missing/invalid — fall through to
		// session-auth path; if that also fails, caller returns 401.
	}

	// Session-auth fallback: user has an authenticated session AND genuinely
	// needs to enroll. These endpoints are not behind middleware.Auth, so we
	// read the session cookie directly.
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
	// Only allow session-auth enrollment when the user actually needs it.
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
	// 1. Resolve enrollment principal from either auth source.
	ctx, err := h.resolveEnrollPrincipal(r)
	if err != nil {
		if errors.Is(err, errAlreadyEnrolled) {
			writeError(w, http.StatusBadRequest, "MFA_ALREADY_ENROLLED", "This account already has two-factor authentication enabled.")
		} else {
			writeError(w, http.StatusUnauthorized, "MFA_ENROLLMENT_EXPIRED", "Enrollment session has expired.")
		}
		return
	}

	// 2. Determine Valkey key. For session-authed users, mint a fresh
	//    enrollment token and set the cookie so /verify and /complete can use it.
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
		// Stamp the session_authed flag so /complete knows not to issue a new session.
		if err := h.valkey.HSet(r.Context(), key, "session_authed", "1").Err(); err != nil {
			slog.Error("mfa enroll: HSet session_authed failed", "error", err)
		}
	} else {
		key = mfaEnrollKeyPrefix + ctx.EnrollToken
	}

	// 3. Load user to check not already enrolled (cookie-path guard; session-path
	//    was already checked in resolveEnrollPrincipal).
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

	// 4. Generate fresh secret. Any pre-existing secret in Valkey (from a
	//    prior /start on the same token — user refreshed mid-flow) is
	//    overwritten; the new call is authoritative.
	secret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		slog.Error("mfa enroll: GenerateTOTPSecret failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// 5. Persist secret into the token key. TTL refresh to full 10 min.
	if err := h.valkey.HSet(r.Context(), key, "secret_base32", secret).Err(); err != nil {
		slog.Error("mfa enroll: HSet secret failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.valkey.Expire(r.Context(), key, mfaEnrollTTL).Err(); err != nil {
		slog.Error("mfa enroll: Expire refresh failed", "error", err)
		// Non-fatal — the key still has whatever TTL it had. Continue.
	}

	// 6. Build provision URI. Read instance_name from config at request time so
	//    the issuer reflects what the admin has configured, not the hostname.
	issuer, err := h.configService.GetInstanceName(r.Context(), h.pool)
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

	// Atomic HIncrBy — increment before doing anything else. If the key is
	// missing (expired or never set), HIncrBy creates it with value 1; we
	// catch that in the "secret missing" check below.
	attempts, err := h.valkey.HIncrBy(r.Context(), key, "verify_attempts", 1).Result()
	if err != nil {
		slog.Error("mfa enroll verify: HIncrBy failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if attempts > mfaEnrollVerifyMaxAttempts {
		// Cap exceeded — nuke the token so any subsequent hit also 401s.
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

	// Code OK — generate recovery codes. Plaintext returned once in the
	// response body; hashes stashed in Valkey under the same token key for
	// the /complete step's PG commit.
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

	// Pull full Valkey state in one round-trip.
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

	encrypted, err := crypto.Encrypt([]byte(secret), h.encryptionKey)
	if err != nil {
		slog.Error("mfa complete: Encrypt failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Read session_authed flag from the Valkey state BEFORE opening the tx.
	// The stamp inside the tx only fires when this is false — the session-
	// authed path already had last_login_at set when the user originally
	// logged in, so we don't overwrite that with the enrollment moment.
	sessionAuthed := state["session_authed"] == "1"

	// PG tx: SetTOTPEnrolled + Insert recovery codes + audit, atomic commit.
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("mfa complete: Begin failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }() // non-actionable after Commit

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

	// Only stamp last_login_at when this enrollment issues a fresh session.
	// The session-authed path (setup-wizard admin, or a user who got admin-
	// reset while holding an active session) already had last_login_at set
	// when the original session was issued.
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

	// Post-tx: destroy enrollment token in Valkey and clear enrollment cookie.
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

	// Only issue a new session when the user did not already have one. On the
	// session-authed path the existing session remains valid — no rotation needed.
	if !sessionAuthed {
		sessionToken, err := h.sessionStore.Create(r.Context(), userID.String(), ip, r.Header.Get("User-Agent"))
		if err != nil {
			slog.Error("mfa complete: session.Create failed", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		setSessionCookie(w, sessionToken, h.secureCookie)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user": userDTO(user),
	})
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

	// Atomic decrement-fetch. Decrement before any other work so concurrent
	// requests can't slip through by racing on the same counter value.
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

	user, err := h.userStore.GetByID(r.Context(), h.pool, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Dispatch on which input field is populated. Recovery path lands in Task 11.
	if req.RecoveryCode != "" {
		h.verifyRecoveryCode(w, r, user, req.RecoveryCode, token, key)
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

	secret, err := crypto.Decrypt(user.TOTPSecretEncrypted, h.encryptionKey)
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

	// Success tx: advance counter + login.succeeded + mfa.challenge_succeeded.
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

	// Post-tx: destroy challenge token, clear cookie, create session.
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
	writeJSON(w, http.StatusOK, map[string]any{"user": userDTO(user)})
}

// writeChallengeFailedAudit writes an mfa.challenge_failed audit row.
// Best-effort: uses its own tx, logs on failure but does not block the caller.
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

// verifyRecoveryCode is the recovery-path branch of PostChallenge.
// It iterates over ALL unused recovery codes in constant time (no short-
// circuit on first match) to prevent timing-based enumeration of the
// remaining-code count, then commits the burn + audit triple atomically.
func (h *MfaHandler) verifyRecoveryCode(w http.ResponseWriter, r *http.Request, user *store.User, plaintext, token, key string) {
	codes, err := h.recoveryCodeStore.ListUnused(r.Context(), h.pool, user.ID)
	if err != nil {
		slog.Error("mfa challenge: ListUnused failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// CONSTANT-TIME ITERATION — do not short-circuit on first match. The
	// variable-time-with-mismatch path would leak the count of unused codes
	// to an attacker timing repeated failures. Accept the ~100ms cost of 10
	// Argon2id verifies per attempt.
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
		// Continue iterating — keep timing uniform even after first match.
	}

	if matchedID == nil {
		h.writeChallengeFailedAudit(r, user.ID.String(), "invalid_recovery_code")
		writeError(w, http.StatusUnauthorized, "MFA_INVALID_RECOVERY_CODE", "Invalid recovery code.")
		return
	}

	// Success tx: mark used + login.succeeded + mfa.challenge_succeeded + mfa.recovery_code_used.
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

	// Post-tx: destroy challenge token, clear cookie, create session.
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
	writeJSON(w, http.StatusOK, map[string]any{"user": userDTO(user)})
}
