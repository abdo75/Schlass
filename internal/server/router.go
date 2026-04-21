// Package server exposes BuildRouter, the single source of truth for HTTP
// route wiring. main.go and the integration test harness both import this
// package so production and test code share exactly one wiring path.
package server

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/abdo75/Schlass/internal/config"
	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/handler"
	"github.com/abdo75/Schlass/internal/middleware"
	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/store"
	"github.com/abdo75/Schlass/internal/web"
)

// RouterDeps bundles every dependency BuildRouter needs. AuditStore is typed
// as the handler.AuditLogger interface (not *store.AuditStore) so integration
// tests can inject a fake that returns an error on Log — letting us exercise
// the "audit write failure rolls back login tx" contract without touching
// production code.
type RouterDeps struct {
	Cfg               *config.Config
	Pool              *pgxpool.Pool
	ValkeyClient      *redis.Client
	ConfigStore       *store.ConfigStore
	UserStore         *store.UserStore
	RecoveryCodeStore *store.RecoveryCodeStore
	AuditStore        handler.AuditLogger
	InstanceConfig    *config.InstanceConfig
	ClientsHandler    *handler.ClientsHandler

	// Rate-limit caps (requests per minute). Defaults come from config.Config;
	// tests override by setting these directly on RouterDeps before BuildRouter.
	LoginRateLimit         int64
	MfaChallengeRateLimit  int64
	PasswordResetRateLimit int64
	TokenRateLimit         int64
	AuthorizeRateLimit     int64
	UserinfoRateLimit      int64

	// HIBPChecker is the Have I Been Pwned k-anonymity client. nil disables
	// the breach-corpus check on all user-supplied password-set handlers.
	// Integration tests set this to nil to avoid live network calls.
	HIBPChecker *crypto.HIBPChecker
}

// BuildRouter assembles the full HTTP handler chain: mux with every route,
// per-route rate limiters, auth middleware on protected endpoints, and the
// global RequestLogging + SecurityHeaders wrappers. Returns an error only if
// AuthHandler construction fails (dummy-hash pre-compute).
func BuildRouter(d RouterDeps) (http.Handler, error) {
	sessionStore := session.NewValkeyStore(d.ValkeyClient, 24*time.Hour)

	healthHandler := handler.NewHealthHandler(d.Pool, d.ValkeyClient)
	setupHandler := handler.NewSetupHandler(d.Pool, d.InstanceConfig, d.ConfigStore, d.UserStore, d.AuditStore, d.HIBPChecker)
	authHandler, err := handler.NewAuthHandler(
		d.Pool, d.ValkeyClient, sessionStore, d.UserStore, d.RecoveryCodeStore, d.AuditStore, d.ConfigStore, d.InstanceConfig, d.Cfg.SchlassPublicURL, d.HIBPChecker,
	)
	if err != nil {
		return nil, err
	}

	authMW := middleware.Auth(sessionStore, d.UserStore, d.AuditStore, d.Pool)

	usersHandler := handler.NewUsersHandler(d.Pool, d.ValkeyClient, d.UserStore, d.AuditStore, sessionStore, d.InstanceConfig, d.RecoveryCodeStore)
	adminSigningKeysHandler := handler.NewAdminSigningKeysHandler(d.Pool, d.AuditStore, d.Cfg.EncryptionKey)
	settingsHandler := handler.NewSettingsHandler(d.Pool, d.InstanceConfig, d.AuditStore, d.Cfg.EncryptionKey)

	mfaHandler := handler.NewMfaHandler(
		d.Pool, d.ValkeyClient, d.UserStore, d.RecoveryCodeStore,
		d.AuditStore, sessionStore, d.InstanceConfig, d.ConfigStore,
		d.Cfg.EncryptionKey,
		d.Cfg.SchlassPublicURL,
	)

	gated := func(perm string, h http.Handler) http.Handler {
		return authMW(middleware.RequirePermission(perm)(h))
	}

	// Setup endpoints are tied to the login cap so an operator that raises
	// login for E2E runs doesn't hit the tiny setup defaults. Minimums kept
	// at 10 (GET) and 5 (POST).
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

	discoveryHandler := handler.NewOIDCDiscoveryHandler(d.Cfg.SchlassPublicURL, d.Pool)
	mux.HandleFunc("GET /.well-known/openid-configuration", discoveryHandler.GetConfiguration)
	mux.HandleFunc("GET /.well-known/jwks.json", discoveryHandler.GetJWKS)

	// Enrollment endpoints are gated only by possession of the schlass_mfa_enroll
	// cookie (validated inside each handler). No middleware.Auth wrapper — the
	// user is NOT authenticated yet at enrollment time.
	mux.Handle("POST /api/mfa/enrollment/start", http.HandlerFunc(mfaHandler.PostEnrollmentStart))
	mux.Handle("POST /api/mfa/enrollment/verify", http.HandlerFunc(mfaHandler.PostEnrollmentVerify))
	mux.Handle("POST /api/mfa/enrollment/complete", http.HandlerFunc(mfaHandler.PostEnrollmentComplete))

	// Challenge endpoint rate-limited per IP — primary brute-force surface.
	mux.Handle("POST /api/mfa/challenge", mfaChallengeRL.Middleware(http.HandlerFunc(mfaHandler.PostChallenge)))

	// Password reset request — enumeration-safe (always 200), rate-limited
	// per IP to cap email spam against unknown users.
	passwordResetHandler, err := handler.NewPasswordResetHandler(
		d.Pool, d.ValkeyClient, d.UserStore,
		store.NewPasswordResetTokenStore(),
		d.AuditStore, sessionStore, d.InstanceConfig,
		d.Cfg.SchlassPublicURL,
		d.HIBPChecker,
	)
	if err != nil {
		return nil, err
	}
	mux.Handle("POST /api/password-reset/request",
		passwordResetRL.Middleware(http.HandlerFunc(passwordResetHandler.PostRequest)))
	// Validate is read-only and enumeration-equivalent to /confirm's not-
	// found path; reuse the same per-IP rate limiter as /request to bound
	// the attack surface without a dedicated bucket.
	mux.Handle("POST /api/password-reset/validate",
		passwordResetRL.Middleware(http.HandlerFunc(passwordResetHandler.PostValidate)))
	// Confirm is not rate-limited: token possession is the auth factor.
	// The token is 32-byte crypto/rand (~256 bits) — brute-force is
	// impossible within the 30-minute TTL, so an IP-level limiter on this
	// endpoint just adds flakiness without raising attacker cost.
	mux.Handle("POST /api/password-reset/confirm",
		http.HandlerFunc(passwordResetHandler.PostConfirm))

	// OIDC authorization endpoint — optionally authenticated (session injected
	// when present, unauthenticated requests redirected to /login).
	authorizeHandler := handler.NewOIDCAuthorizeHandler(d.Pool, sessionStore, d.AuditStore, d.Cfg.SchlassPublicURL)
	optionalAuth := middleware.OptionalAuth(sessionStore, d.UserStore, d.AuditStore, d.Pool)
	mux.Handle("GET /authorize", authorizeRL.Middleware(optionalAuth(http.HandlerFunc(authorizeHandler.Handle))))

	// OIDC token endpoint — client auth happens inside the handler.
	tokenHandler := handler.NewOIDCTokenHandler(
		d.Pool, d.ValkeyClient,
		d.UserStore, d.AuditStore,
		sessionStore,
		d.Cfg.SchlassPublicURL, d.Cfg.EncryptionKey,
		d.TokenRateLimit,
	)
	mux.Handle("POST /token", http.HandlerFunc(tokenHandler.Handle))

	// OIDC userinfo endpoint — gated by Bearer access token.
	userInfoHandler := handler.NewOIDCUserInfoHandler(d.Pool, d.AuditStore)
	bearerAuth := middleware.BearerAuth(middleware.BearerAuthDeps{
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
