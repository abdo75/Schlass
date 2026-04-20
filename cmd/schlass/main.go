package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/abdo75/Schlass/internal/bootstrap"
	"github.com/abdo75/Schlass/internal/config"
	"github.com/abdo75/Schlass/internal/database"
	"github.com/abdo75/Schlass/internal/handler"
	"github.com/abdo75/Schlass/internal/oidc"
	"github.com/abdo75/Schlass/internal/server"
	"github.com/abdo75/Schlass/internal/store"
	"github.com/abdo75/Schlass/internal/valkey"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()

	slog.Info("running database migrations")
	if err := database.RunMigrations(cfg.MigrationsDatabaseURL); err != nil {
		slog.Error("migrations failed", "error", err)
		os.Exit(1)
	}

	pool, err := database.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	valkeyClient, err := valkey.NewClient(ctx, cfg.ValkeyURL)
	if err != nil {
		slog.Error("failed to connect to Valkey", "error", err)
		os.Exit(1)
	}
	defer func() { _ = valkeyClient.Close() }() // error on Close is non-actionable during shutdown

	configStore := store.NewConfigStore()
	userStore := store.NewUserStore()
	auditStore := store.NewAuditStore()
	recoveryCodeStore := store.NewRecoveryCodeStore()
	configService := config.NewConfigService(configStore, cfg.EncryptionKey)

	slog.Info("bootstrapping signing key")
	if err := oidc.BootstrapSigningKey(ctx, pool, auditStore, cfg.EncryptionKey); err != nil {
		slog.Error("signing-key bootstrap failed", "error", err)
		os.Exit(1)
	}

	retireCutoff := time.Now().Add(-(15*time.Minute + 24*time.Hour + 30*time.Second))
	if err := oidc.RetireSweep(ctx, pool, auditStore, retireCutoff); err != nil {
		slog.Warn("signing-key retire sweep failed", "error", err)
		// Non-fatal — orphan retiring keys just stay listed.
	}

	// Developer-mode OIDC client seeding. No-op unless SCHLASS_DEV=1 AND
	// SCHLASS_PUBLIC_URL is http. Idempotent against the seed-client name.
	if err := bootstrap.SeedDevClient(ctx, pool, os.Getenv("SCHLASS_DEV"), os.Getenv("SCHLASS_DEV_SECRET"), cfg.SchlassPublicURL); err != nil {
		slog.Error("dev-seed failed", "error", err)
		os.Exit(1)
	}

	publicURL, err := url.Parse(cfg.SchlassPublicURL)
	if err != nil {
		slog.Error("failed to parse SCHLASS_PUBLIC_URL", "error", err)
		os.Exit(1)
	}

	clientStore := store.NewClientStore()
	clientsHandler := handler.NewClientsHandler(pool, valkeyClient, clientStore, auditStore, publicURL)

	h, err := server.BuildRouter(server.RouterDeps{
		Cfg:                   cfg,
		Pool:                  pool,
		ValkeyClient:          valkeyClient,
		ConfigStore:           configStore,
		UserStore:             userStore,
		RecoveryCodeStore:     recoveryCodeStore,
		AuditStore:            auditStore,
		ConfigService:         configService,
		LoginRateLimit:         cfg.LoginRateLimit,
		MfaChallengeRateLimit:  cfg.MfaChallengeRateLimit,
		PasswordResetRateLimit: cfg.PasswordResetRateLimit,
		AuthorizeRateLimit:     cfg.AuthorizeRateLimit,
		UserinfoRateLimit:      cfg.UserinfoRateLimit,
		ClientsHandler:         clientsHandler,
	})
	if err != nil {
		slog.Error("failed to build router", "error", err)
		os.Exit(1)
	}

	httpServer := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      h,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	errChan := make(chan error, 1)
	go func() {
		slog.Info("server starting", "port", cfg.Port)
		errChan <- httpServer.ListenAndServe()
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		slog.Info("shutdown signal received", "signal", sig)
	case err := <-errChan:
		slog.Error("server error", "error", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("forced shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("server stopped gracefully")
}
