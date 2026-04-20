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
	ConfigService     *config.ConfigService
	ClientsHandler    *handler.ClientsHandler

	// LoginRateLimit overrides the per-IP /api/login rate-limit cap. Zero (the
	// production default path) means "use 5/min". Tests that need to drive many
	// login attempts from the same virtual IP set this to a large value so the
	// rate limiter never trips and the test can exercise application-level
	// lockout semantics in isolation.
	LoginRateLimit int64
	// MfaChallengeRateLimit overrides the per-IP /api/mfa/challenge rate-limit
	// cap. Zero means "use 5/min". E2E tests set this to a large value so the
	// limiter doesn't trip across repeated challenge requests.
	MfaChallengeRateLimit int64
	// PasswordResetRateLimit overrides the per-IP /api/password-reset/request
	// rate-limit cap. Zero means "use 5/min". Tests raise this so the guard
	// doesn't mask enumeration-safety assertions.
	PasswordResetRateLimit int64
	// TokenRateLimit overrides the per-client_id /token rate-limit cap. Zero
	// means "use 60/min". Integration tests that want to exercise the 429 path
	// set this to a small value (e.g. 3).
	TokenRateLimit int64
	// AuthorizeRateLimit overrides the per-IP /authorize rate-limit cap.
	// Zero means "use 60/min". Tests set large values to avoid flake.
	AuthorizeRateLimit int64
	// UserinfoRateLimit overrides the per-IP /userinfo rate-limit cap.
	// Zero means "use 60/min".
	UserinfoRateLimit int64
}

// BuildRouter assembles the full HTTP handler chain: mux with every route,
// per-route rate limiters, auth middleware on protected endpoints, and the
// global RequestLogging + SecurityHeaders wrappers. Returns an error only if
// AuthHandler construction fails (dummy-hash pre-compute).
func BuildRouter(d RouterDeps) (http.Handler, error) {
	sessionStore := session.NewValkeyStore(d.ValkeyClient, 24*time.Hour)

	healthHandler := handler.NewHealthHandler(d.Pool, d.ValkeyClient)
	setupHandler := handler.NewSetupHandler(d.Pool, d.ConfigService, d.ConfigStore, d.UserStore, d.AuditStore)
	authHandler, err := handler.NewAuthHandler(
		d.Pool, d.ValkeyClient, sessionStore, d.UserStore, d.RecoveryCodeStore, d.AuditStore, d.ConfigStore, d.ConfigService, d.Cfg.SchlassPublicURL,
	)
	if err != nil {
		return nil, err
	}

	authMW := middleware.Auth(sessionStore, d.UserStore, d.AuditStore, d.Pool)

	usersHandler := handler.NewUsersHandler(d.Pool, d.ValkeyClient, d.UserStore, d.AuditStore, sessionStore, d.ConfigService, d.RecoveryCodeStore)
	adminSigningKeysHandler := handler.NewAdminSigningKeysHandler(d.Pool, d.AuditStore, d.Cfg.EncryptionKey)
	settingsHandler := handler.NewSettingsHandler(d.Pool, d.ConfigService, d.AuditStore, d.Cfg.EncryptionKey)

	mfaHandler := handler.NewMfaHandler(
		d.Pool, d.ValkeyClient, d.UserStore, d.RecoveryCodeStore,
		d.AuditStore, sessionStore, d.ConfigService, d.ConfigStore,
		d.Cfg.EncryptionKey,
		d.Cfg.SchlassPublicURL,
	)

	gated := func(perm string, h http.Handler) http.Handler {
		return authMW(middleware.RequirePermission(perm)(h))
	}

	setupGetLimit := int64(10)
	setupPostLimit := int64(5)
	loginLimit := int64(5)
	if d.LoginRateLimit > 0 {
		loginLimit = d.LoginRateLimit
		// When the operator has raised the login cap (e.g. for E2E test
		// runs) it would be surprising to leave the sibling /api/setup
		// limits at their tiny defaults, because those are just as easy
		// to trip from a headless browser. Scale them to the same cap.
		setupGetLimit = d.LoginRateLimit
		setupPostLimit = d.LoginRateLimit
	}
	setupGetRL := middleware.NewRateLimiter(d.ValkeyClient, "ratelimit:setup:get", setupGetLimit, time.Minute)
	setupPostRL := middleware.NewRateLimiter(d.ValkeyClient, "ratelimit:setup:post", setupPostLimit, time.Minute)
	loginRL := middleware.NewRateLimiter(d.ValkeyClient, "ratelimit:login", loginLimit, time.Minute)
	mfaLimit := int64(5)
	if d.MfaChallengeRateLimit > 0 {
		mfaLimit = d.MfaChallengeRateLimit
	}
	mfaChallengeRL := middleware.NewRateLimiter(d.ValkeyClient, "ratelimit:mfa", mfaLimit, time.Minute)
	passwordResetLimit := int64(5)
	if d.PasswordResetRateLimit > 0 {
		passwordResetLimit = d.PasswordResetRateLimit
	}
	passwordResetRL := middleware.NewRateLimiter(d.ValkeyClient, "ratelimit:password_reset", passwordResetLimit, time.Minute)
	authorizeLimit := int64(60)
	if d.AuthorizeRateLimit > 0 {
		authorizeLimit = d.AuthorizeRateLimit
	}
	userinfoLimit := int64(60)
	if d.UserinfoRateLimit > 0 {
		userinfoLimit = d.UserinfoRateLimit
	}
	authorizeRL := middleware.NewRateLimiter(d.ValkeyClient, "ratelimit:authorize", authorizeLimit, time.Minute)
	userinfoRL := middleware.NewRateLimiter(d.ValkeyClient, "ratelimit:userinfo", userinfoLimit, time.Minute)

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
		d.AuditStore, sessionStore, d.ConfigService,
		d.Cfg.SchlassPublicURL,
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
