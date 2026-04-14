package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/schlass/schlass/internal/config"
	"github.com/schlass/schlass/internal/database"
	"github.com/schlass/schlass/internal/handler"
	"github.com/schlass/schlass/internal/middleware"
	"github.com/schlass/schlass/internal/store"
	"github.com/schlass/schlass/internal/valkey"
	"github.com/schlass/schlass/internal/web"
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
	defer valkeyClient.Close()

	configStore := store.NewConfigStore()
	userStore := store.NewUserStore()
	auditStore := store.NewAuditStore()
	configService := config.NewConfigService(configStore, cfg.EncryptionKey)

	healthHandler := handler.NewHealthHandler(pool, valkeyClient)
	setupHandler := handler.NewSetupHandler(pool, configService, configStore, userStore, auditStore)

	setupGetRL := middleware.NewRateLimiter(valkeyClient, "ratelimit:setup:get", 10, time.Minute)
	setupPostRL := middleware.NewRateLimiter(valkeyClient, "ratelimit:setup:post", 5, time.Minute)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", healthHandler.GetHealth)
	mux.Handle("GET /api/setup", setupGetRL.Middleware(http.HandlerFunc(setupHandler.GetSetup)))
	mux.Handle("POST /api/setup", setupPostRL.Middleware(http.HandlerFunc(setupHandler.PostSetup)))
	mux.Handle("/", web.SPAHandler())

	var h http.Handler = mux
	h = middleware.RequestLogging(h)
	h = middleware.SecurityHeaders(h)

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      h,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	errChan := make(chan error, 1)
	go func() {
		slog.Info("server starting", "port", cfg.Port)
		errChan <- server.ListenAndServe()
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

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("forced shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("server stopped gracefully")
}
