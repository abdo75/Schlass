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
	Cfg           *config.Config
	Pool          *pgxpool.Pool
	ValkeyClient  *redis.Client
	ConfigStore   *store.ConfigStore
	UserStore     *store.UserStore
	AuditStore    handler.AuditLogger
	ConfigService *config.ConfigService

	// LoginRateLimit overrides the per-IP /api/login rate-limit cap. Zero (the
	// production default path) means "use 5/min". Tests that need to drive many
	// login attempts from the same virtual IP set this to a large value so the
	// rate limiter never trips and the test can exercise application-level
	// lockout semantics in isolation.
	LoginRateLimit int64
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
		d.Pool, sessionStore, d.UserStore, d.AuditStore, d.ConfigStore, d.Cfg.SchlassPublicURL,
	)
	if err != nil {
		return nil, err
	}

	authMW := middleware.Auth(sessionStore, d.UserStore, d.AuditStore, d.Pool)

	usersHandler := handler.NewUsersHandler(d.Pool, d.UserStore, d.AuditStore, sessionStore, d.ConfigService)

	adminRoleGate := middleware.RequireRole("super_admin")
	admin := func(h http.Handler) http.Handler {
		return authMW(adminRoleGate(h))
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

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", healthHandler.GetHealth)
	mux.Handle("GET /api/setup", setupGetRL.Middleware(http.HandlerFunc(setupHandler.GetSetup)))
	mux.Handle("POST /api/setup", setupPostRL.Middleware(http.HandlerFunc(setupHandler.PostSetup)))

	mux.Handle("POST /api/login", loginRL.Middleware(http.HandlerFunc(authHandler.PostLogin)))
	mux.Handle("POST /api/logout", authMW(http.HandlerFunc(authHandler.PostLogout)))
	mux.Handle("GET /api/me", authMW(http.HandlerFunc(authHandler.GetMe)))

	mux.Handle("GET /api/users", admin(http.HandlerFunc(usersHandler.List)))
	mux.Handle("POST /api/users", admin(http.HandlerFunc(usersHandler.Create)))
	mux.Handle("GET /api/users/{id}", admin(http.HandlerFunc(usersHandler.Get)))
	mux.Handle("PATCH /api/users/{id}", admin(http.HandlerFunc(usersHandler.Update)))
	mux.Handle("POST /api/users/{id}/disable", admin(http.HandlerFunc(usersHandler.Disable)))
	mux.Handle("POST /api/users/{id}/enable", admin(http.HandlerFunc(usersHandler.Enable)))
	mux.Handle("POST /api/users/{id}/reset-password", admin(http.HandlerFunc(usersHandler.ResetPassword)))
	mux.Handle("DELETE /api/users/{id}", admin(http.HandlerFunc(usersHandler.Delete)))
	mux.Handle("GET /api/users/{id}/sessions", admin(http.HandlerFunc(usersHandler.ListSessions)))
	mux.Handle("DELETE /api/users/{id}/sessions", admin(http.HandlerFunc(usersHandler.TerminateAllSessions)))
	mux.Handle("DELETE /api/users/{id}/sessions/{token}", admin(http.HandlerFunc(usersHandler.TerminateSession)))

	mux.Handle("/", web.SPAHandler())

	var h http.Handler = mux
	h = middleware.RequestLogging(h)
	h = middleware.SecurityHeaders(h)
	return h, nil
}
