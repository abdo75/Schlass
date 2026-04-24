// Package server exposes BuildRouter — the single source of truth for HTTP
// route wiring. main.go and the integration test harness both import this so
// production and test code share exactly one wiring path.
package server

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/auth"

	"github.com/abdo75/Schlass/internal/authserver"
	"github.com/abdo75/Schlass/internal/clients"
	"github.com/abdo75/Schlass/internal/config"
	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/instanceconfig"
	"github.com/abdo75/Schlass/internal/middleware"
	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/settings"
	authsigningkeys "github.com/abdo75/Schlass/internal/signingkeys"
	"github.com/abdo75/Schlass/internal/users"
	"github.com/abdo75/Schlass/internal/web"
)

// RouterDeps — AuditStore is audit.PseudonymizingLogger (not *store.AuditStore) so
// integration tests can inject a fake that errors on Log to exercise the
// "audit write failure rolls back login tx" contract.
type RouterDeps struct {
	Cfg               *config.Env
	Pool              *pgxpool.Pool
	ValkeyClient      *redis.Client
	ConfigStore       *instanceconfig.Store
	UserStore         *users.Store
	RecoveryCodeStore *auth.RecoveryCodeStore
	AuditStore        audit.PseudonymizingLogger
	InstanceConfig    *instanceconfig.Service
	ClientsHandler    *clients.Handler

	LoginRateLimit         int64
	MfaChallengeRateLimit  int64
	PasswordResetRateLimit int64
	TokenRateLimit         int64
	AuthorizeRateLimit     int64
	UserinfoRateLimit      int64

	// nil disables HIBP breach-corpus check on all password-set handlers.
	HIBPChecker *crypto.HIBPChecker
}

func BuildRouter(d RouterDeps) (http.Handler, error) {
	sessionStore := session.NewValkeyStore(d.ValkeyClient, 24*time.Hour)

	healthHandler := NewHealthHandler(d.Pool, d.ValkeyClient)
	setupHandler := NewSetupHandler(d.Pool, d.InstanceConfig, d.ConfigStore, d.UserStore, d.AuditStore, d.HIBPChecker)
	authHandler, err := auth.NewHandler(
		d.Pool, d.ValkeyClient, sessionStore, d.UserStore, d.RecoveryCodeStore, d.AuditStore, d.ConfigStore, d.InstanceConfig, d.Cfg.SchlassPublicURL, d.HIBPChecker,
	)
	if err != nil {
		return nil, err
	}

	authMW := auth.Middleware(sessionStore, d.UserStore, d.AuditStore, d.Pool)

	usersHandler := users.NewHandler(d.Pool, d.ValkeyClient, d.UserStore, d.AuditStore, sessionStore, d.InstanceConfig, d.RecoveryCodeStore)
	adminSigningKeysHandler := authsigningkeys.NewHandler(d.Pool, d.AuditStore, d.Cfg.EncryptionKey)
	settingsHandler := settings.NewHandler(d.Pool, d.InstanceConfig, d.AuditStore, d.Cfg.EncryptionKey)

	mfaHandler := auth.NewMFAHandler(
		d.Pool, d.ValkeyClient, d.UserStore, d.RecoveryCodeStore,
		d.AuditStore, sessionStore, d.InstanceConfig, d.ConfigStore,
		d.Cfg.EncryptionKey,
		d.Cfg.SchlassPublicURL,
	)

	gated := func(perm string, h http.Handler) http.Handler {
		return authMW(users.RequirePermission(perm)(h))
	}

	// Setup tied to login cap so E2E raising login doesn't hit tiny setup defaults.
	setupGetLimit := d.LoginRateLimit
	if setupGetLimit < 10 {
		setupGetLimit = 10
	}
	setupPostLimit := d.LoginRateLimit
	if setupPostLimit < 5 {
		setupPostLimit = 5
	}
	setupGetRL := middleware.NewRateLimiter(d.ValkeyClient, "ratelimit:setup:get", setupGetLimit, time.Minute)
	setupPostRL := middleware.NewRateLimiter(d.ValkeyClient, "ratelimit:setup:post", setupPostLimit, time.Minute)
	loginRL := middleware.NewRateLimiter(d.ValkeyClient, "ratelimit:login", d.LoginRateLimit, time.Minute)
	loginRL.FailClosed = true
	mfaChallengeRL := middleware.NewRateLimiter(d.ValkeyClient, "ratelimit:mfa", d.MfaChallengeRateLimit, time.Minute)
	mfaChallengeRL.FailClosed = true
	passwordResetRL := middleware.NewRateLimiter(d.ValkeyClient, "ratelimit:password_reset", d.PasswordResetRateLimit, time.Minute)
	passwordResetRL.FailClosed = true
	authorizeRL := middleware.NewRateLimiter(d.ValkeyClient, "ratelimit:authorize", d.AuthorizeRateLimit, time.Minute)
	userinfoRL := middleware.NewRateLimiter(d.ValkeyClient, "ratelimit:userinfo", d.UserinfoRateLimit, time.Minute)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", healthHandler.GetHealth)
	mux.Handle("GET /api/setup", setupGetRL.Middleware(http.HandlerFunc(setupHandler.GetSetup)))
	mux.Handle("POST /api/setup", setupPostRL.Middleware(http.HandlerFunc(setupHandler.PostSetup)))

	mux.Handle("POST /api/login", loginRL.Middleware(http.HandlerFunc(authHandler.PostLogin)))
	mux.Handle("POST /api/logout", authMW(http.HandlerFunc(authHandler.PostLogout)))
	mux.Handle("GET /api/me", authMW(http.HandlerFunc(authHandler.GetMe)))
	mux.Handle("POST /api/change-password", authMW(http.HandlerFunc(authHandler.PostChangePassword)))
	mux.Handle("POST /api/me/mfa/disable", authMW(http.HandlerFunc(authHandler.PostDisableMfa)))

	mux.Handle("GET /api/users", gated("users.list", http.HandlerFunc(usersHandler.List)))
	mux.Handle("POST /api/users", gated("users.create", http.HandlerFunc(usersHandler.Create)))
	mux.Handle("GET /api/users/{id}", gated("users.read", http.HandlerFunc(usersHandler.Get)))
	mux.Handle("PATCH /api/users/{id}", gated("users.update", http.HandlerFunc(usersHandler.Update)))
	mux.Handle("POST /api/users/{id}/disable", gated("users.disable", http.HandlerFunc(usersHandler.Disable)))
	mux.Handle("POST /api/users/{id}/enable", gated("users.enable", http.HandlerFunc(usersHandler.Enable)))
	mux.Handle("POST /api/users/{id}/reset-password", gated("users.reset_password", http.HandlerFunc(usersHandler.ResetPassword)))
	mux.Handle("POST /api/users/{id}/reset-mfa", gated("users.reset_mfa", http.HandlerFunc(usersHandler.ResetMFA)))
	mux.Handle("DELETE /api/users/{id}", gated("users.delete", http.HandlerFunc(usersHandler.Delete)))
	mux.Handle("GET /api/users/{id}/sessions", gated("users.sessions.read", http.HandlerFunc(usersHandler.ListSessions)))
	mux.Handle("DELETE /api/users/{id}/sessions", gated("users.sessions.terminate", http.HandlerFunc(usersHandler.TerminateAllSessions)))
	mux.Handle("DELETE /api/users/{id}/sessions/{token}", gated("users.sessions.terminate", http.HandlerFunc(usersHandler.TerminateSession)))

	mux.Handle("GET /api/clients", gated("clients.list", http.HandlerFunc(d.ClientsHandler.GetList)))
	mux.Handle("POST /api/clients", gated("clients.create", http.HandlerFunc(d.ClientsHandler.PostCreate)))
	mux.Handle("GET /api/clients/{id}", gated("clients.read", http.HandlerFunc(d.ClientsHandler.GetOne)))
	mux.Handle("PATCH /api/clients/{id}", gated("clients.update", http.HandlerFunc(d.ClientsHandler.PatchOne)))
	mux.Handle("POST /api/clients/{id}/disable", gated("clients.disable", http.HandlerFunc(d.ClientsHandler.PostDisable)))
	mux.Handle("POST /api/clients/{id}/enable", gated("clients.enable", http.HandlerFunc(d.ClientsHandler.PostEnable)))
	mux.Handle("POST /api/clients/{id}/rotate-secret", gated("clients.rotate_secret", http.HandlerFunc(d.ClientsHandler.PostRotateSecret)))
	mux.Handle("DELETE /api/clients/{id}", gated("clients.delete", http.HandlerFunc(d.ClientsHandler.DeleteOne)))

	mux.Handle("GET /api/admin/signing-keys",
		gated("signing_keys.list", http.HandlerFunc(adminSigningKeysHandler.GetList)))
	mux.Handle("POST /api/admin/signing-keys/rotate",
		gated("signing_keys.rotate", http.HandlerFunc(adminSigningKeysHandler.Rotate)))
	mux.Handle("POST /api/admin/signing-keys/{kid}/retire-now",
		gated("signing_keys.retire", http.HandlerFunc(adminSigningKeysHandler.EmergencyRetire)))

	mux.Handle("GET /api/settings",
		gated("settings.read", http.HandlerFunc(settingsHandler.GetAll)))
	mux.Handle("PATCH /api/settings/general",
		gated("settings.write", http.HandlerFunc(settingsHandler.PatchGeneral)))
	mux.Handle("PATCH /api/settings/security",
		gated("settings.write", http.HandlerFunc(settingsHandler.PatchSecurity)))
	mux.Handle("PATCH /api/settings/tokens",
		gated("settings.write", http.HandlerFunc(settingsHandler.PatchTokens)))
	mux.Handle("PATCH /api/settings/email",
		gated("settings.write", http.HandlerFunc(settingsHandler.PatchEmail)))
	mux.Handle("POST /api/settings/email/test",
		gated("settings.write", http.HandlerFunc(settingsHandler.TestEmail)))

	discoveryHandler := authserver.NewDiscoveryHandler(d.Cfg.SchlassPublicURL, d.Pool)
	mux.HandleFunc("GET /.well-known/openid-configuration", discoveryHandler.GetConfiguration)
	mux.HandleFunc("GET /.well-known/jwks.json", discoveryHandler.GetJWKS)

	// Enrollment endpoints are gated by possession of schlass_mfa_enroll cookie
	// (validated inside each handler). No authMW — user is NOT authenticated yet.
	mux.Handle("POST /api/mfa/enrollment/start", http.HandlerFunc(mfaHandler.PostEnrollmentStart))
	mux.Handle("POST /api/mfa/enrollment/verify", http.HandlerFunc(mfaHandler.PostEnrollmentVerify))
	mux.Handle("POST /api/mfa/enrollment/complete", http.HandlerFunc(mfaHandler.PostEnrollmentComplete))

	mux.Handle("POST /api/mfa/challenge", mfaChallengeRL.Middleware(http.HandlerFunc(mfaHandler.PostChallenge)))

	resetPepper, err := crypto.DeriveTokenPepper(d.Cfg.EncryptionKey)
	if err != nil {
		return nil, err
	}
	passwordResetHandler, err := auth.NewPasswordResetHandler(
		d.Pool, d.ValkeyClient, d.UserStore,
		auth.NewTokenStore(resetPepper),
		d.AuditStore, sessionStore, d.InstanceConfig,
		d.Cfg.SchlassPublicURL,
		d.HIBPChecker,
	)
	if err != nil {
		return nil, err
	}
	mux.Handle("POST /api/password-reset/request",
		passwordResetRL.Middleware(http.HandlerFunc(passwordResetHandler.PostRequest)))
	mux.Handle("POST /api/password-reset/validate",
		passwordResetRL.Middleware(http.HandlerFunc(passwordResetHandler.PostValidate)))
	// Confirm is NOT rate-limited: token possession is the auth. The token is
	// 32-byte crypto/rand (~256 bits) — brute-force infeasible in 30-min TTL,
	// IP limiter just adds flakiness without raising attacker cost.
	mux.Handle("POST /api/password-reset/confirm",
		http.HandlerFunc(passwordResetHandler.PostConfirm))

	authorizeHandler := authserver.NewAuthorizeHandler(d.Pool, sessionStore, d.AuditStore, d.Cfg.SchlassPublicURL)
	optionalAuth := auth.OptionalMiddleware(sessionStore, d.UserStore, d.AuditStore, d.Pool)
	mux.Handle("GET /authorize", authorizeRL.Middleware(optionalAuth(http.HandlerFunc(authorizeHandler.Handle))))

	tokenHandler := authserver.NewTokenHandler(
		d.Pool, d.ValkeyClient,
		d.UserStore, d.AuditStore,
		sessionStore,
		d.InstanceConfig,
		d.Cfg.SchlassPublicURL, d.Cfg.EncryptionKey,
		d.TokenRateLimit,
	)
	mux.Handle("POST /token", http.HandlerFunc(tokenHandler.Handle))

	userInfoHandler := authserver.NewUserInfoHandler(d.Pool, d.AuditStore)
	bearerAuth := authserver.BearerAuth(authserver.BearerAuthDeps{
		Pool:      d.Pool,
		UserStore: d.UserStore,
		Valkey:    d.ValkeyClient,
		Issuer:    d.Cfg.SchlassPublicURL,
	})
	mux.Handle("GET /userinfo", userinfoRL.Middleware(bearerAuth(http.HandlerFunc(userInfoHandler.Handle))))

	mux.Handle("/", web.SPAHandler())

	var h http.Handler = mux
	h = middleware.RequestLogging(h)
	h = middleware.SecurityHeaders(h)
	return h, nil
}
