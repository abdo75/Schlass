package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
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
	encryptionKey     []byte
	issuer            string // human-readable issuer for the otpauth:// URI — derived from SCHLASS_PUBLIC_URL host at construction time
	secureCookie      bool   // Secure flag on Set-Cookie — true iff SCHLASS_PUBLIC_URL is https
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
		encryptionKey:     encryptionKey,
		issuer:            issuerFromPublicURL(publicURL),
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
	mfaEnrollTTL    = 10 * time.Minute    //nolint:unused // used by Tasks 7-11
	mfaChallengeTTL = 120 * time.Second   //nolint:unused // used by Tasks 7-11
)

// Attempt caps for the enrollment-verify and challenge endpoints.
const (
	mfaEnrollVerifyMaxAttempts = 5
	mfaChallengeMaxAttempts    = 5 //nolint:unused // used by Tasks 10-11
)

// Valkey key prefixes. Intentionally not the same prefix as the opaque-
// session store (internal/session) to keep MFA transient state visibly
// separate from admin sessions.
const (
	mfaEnrollKeyPrefix    = "mfa:enroll:"
	mfaChallengeKeyPrefix = "mfa:challenge:" //nolint:unused // used by Tasks 10-11
)

func (h *MfaHandler) PostEnrollmentStart(w http.ResponseWriter, r *http.Request) {
	// 1. Validate enrollment token from cookie.
	tokenCookie, err := r.Cookie(MfaEnrollCookieName)
	if err != nil || tokenCookie.Value == "" {
		writeError(w, http.StatusUnauthorized, "MFA_ENROLLMENT_EXPIRED", "Enrollment session has expired.")
		return
	}
	token := tokenCookie.Value
	key := mfaEnrollKeyPrefix + token

	// 2. Load enrollment state from Valkey.
	userIDStr, err := h.valkey.HGet(r.Context(), key, "user_id").Result()
	if err != nil || userIDStr == "" {
		writeError(w, http.StatusUnauthorized, "MFA_ENROLLMENT_EXPIRED", "Enrollment session has expired.")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		slog.Error("mfa enroll: malformed user_id in valkey")
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// 3. Load user to build provision URI + check not already enrolled.
	user, err := h.userStore.GetByID(r.Context(), h.pool, userID)
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

	// 5. Persist secret into the same token key. TTL refresh to full 10 min.
	if err := h.valkey.HSet(r.Context(), key, "secret_base32", secret).Err(); err != nil {
		slog.Error("mfa enroll: HSet secret failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.valkey.Expire(r.Context(), key, mfaEnrollTTL).Err(); err != nil {
		slog.Error("mfa enroll: Expire refresh failed", "error", err)
		// Non-fatal — the key still has whatever TTL it had. Continue.
	}

	// 6. Build provision URI.
	uri, err := crypto.BuildProvisionURI(h.issuer, user.Email, secret)
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

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("mfa complete: Commit failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Post-tx: destroy enrollment token in Valkey, clear enrollment cookie,
	// create session, set session cookie.
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

	sessionToken, err := h.sessionStore.Create(r.Context(), userID.String(), ip, r.Header.Get("User-Agent"))
	if err != nil {
		slog.Error("mfa complete: session.Create failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	setSessionCookie(w, sessionToken, h.secureCookie)

	writeJSON(w, http.StatusOK, map[string]any{
		"user": userDTO(user),
	})
}

func (h *MfaHandler) PostChallenge(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "MFA challenge not yet implemented.")
}

// issuerFromPublicURL extracts a human-readable issuer for the otpauth://
// URI (e.g. https://auth.example.com → "auth.example.com"). Falls back to
// "Schlass" if the URL is empty or unparseable.
func issuerFromPublicURL(publicURL string) string {
	u, err := url.Parse(publicURL)
	if err != nil || u.Host == "" {
		return "Schlass"
	}
	return u.Host
}
