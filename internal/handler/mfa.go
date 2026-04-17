package handler

import (
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/abdo75/Schlass/internal/config"
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
	mfaEnrollVerifyMaxAttempts = 5 //nolint:unused // used by Tasks 8, 10
	mfaChallengeMaxAttempts    = 5 //nolint:unused // used by Tasks 10-11
)

// Valkey key prefixes. Intentionally not the same prefix as the opaque-
// session store (internal/session) to keep MFA transient state visibly
// separate from admin sessions.
const (
	mfaEnrollKeyPrefix    = "mfa:enroll:"    //nolint:unused // used by Tasks 7-9
	mfaChallengeKeyPrefix = "mfa:challenge:" //nolint:unused // used by Tasks 10-11
)

func (h *MfaHandler) PostEnrollmentStart(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "MFA enrollment start not yet implemented.")
}

func (h *MfaHandler) PostEnrollmentVerify(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "MFA enrollment verify not yet implemented.")
}

func (h *MfaHandler) PostEnrollmentComplete(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "MFA enrollment complete not yet implemented.")
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
