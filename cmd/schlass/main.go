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

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/auth"
	"github.com/abdo75/Schlass/internal/clients"
	"github.com/abdo75/Schlass/internal/config"
	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/database"
	"github.com/abdo75/Schlass/internal/instanceconfig"
	"github.com/abdo75/Schlass/internal/recovery"
	"github.com/abdo75/Schlass/internal/server"
	"github.com/abdo75/Schlass/internal/signingkeys"
	"github.com/abdo75/Schlass/internal/users"
	"github.com/abdo75/Schlass/internal/valkey"
)

func main() {
	// Send all logs to stdout as JSON
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	// Subcommand dispatch. Single-shot CLI utilities exit before the
	// HTTP server boot path runs.
	if len(os.Args) > 1 && os.Args[1] == "recovery-reset" {
		if err := recovery.Run(os.Args[2:]); err != nil {
			slog.Error("recovery-reset failed", "error", err)
			os.Exit(1)
		}
		return
	}

	// Load env vars
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()

	// Apply any pending schema changes.
	slog.Info("running database migrations")
	if err := database.RunMigrations(cfg.MigrationsDatabaseURL); err != nil {
		slog.Error("migrations failed", "error", err)
		os.Exit(1)
	}

	// Open a pool of reusable connections to the DB.
	pool, err := database.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	// Connect to Valkey (in-memory store)
	valkeyClient, err := valkey.NewClient(ctx, cfg.ValkeyURL)
	if err != nil {
		slog.Error("failed to connect to Valkey", "error", err)
		os.Exit(1)
	}
	defer func() { _ = valkeyClient.Close() }() // error on Close is non-actionable during shutdown

	// Build the store objects that handlers use to read and write each table.
	configStore := instanceconfig.NewStore()
	userStore := users.NewStore()
	recoveryCodeStore := auth.NewRecoveryCodeStore()
	instanceConfig := instanceconfig.NewService(configStore, cfg.EncryptionKey)

	// Read the IP coarsening mode once at boot. Anything that fails to
	// parse falls back to IPModeCoarse — same default the migration
	// seeds, so the only way to land here is a hand-edited row.
	ipModeRaw, _ := instanceConfig.AuditClientIPMode(ctx, pool)
	ipMode, err := audit.ParseIPMode(ipModeRaw)
	if err != nil {
		slog.Warn("audit: invalid client_ip_mode in instance_config, falling back to coarse", "got", ipModeRaw, "error", err)
		ipMode = audit.IPModeCoarse
	}
	auditStore := audit.NewStoreWithIPMode(ipMode)
	slog.Info("audit store ready", "ip_mode", ipMode)

	// Make sure a signing key exists so we can issue OIDC tokens. Generates one on first boot.
	slog.Info("bootstrapping signing key")
	if err := signingkeys.Bootstrap(ctx, pool, auditStore, cfg.EncryptionKey); err != nil {
		slog.Error("signing-key bootstrap failed", "error", err)
		os.Exit(1)
	}

	// Clean up old signing keys that are past their grace window.
	retireCutoff := time.Now().Add(-(15*time.Minute + 24*time.Hour + 30*time.Second))
	if err := signingkeys.RetireSweep(ctx, pool, auditStore, retireCutoff); err != nil {
		slog.Warn("signing-key retire sweep failed", "error", err)
		// Non-fatal — orphan retiring keys just stay listed.
	}

	// Nightly cleanup of expired reset tokens + auth codes. Bound to ctx so
	// graceful shutdown cancels cleanly. 0 interval disables.
	go server.StartSweeper(ctx, pool, time.Duration(cfg.SweeperIntervalSecs)*time.Second, auditStore)

	// Create a test OIDC client when running in dev mode. Skipped in prod.
	if err := server.SeedDevClient(ctx, pool, os.Getenv("SCHLASS_DEV"), os.Getenv("SCHLASS_DEV_SECRET"), cfg.SchlassPublicURL); err != nil {
		slog.Error("dev-seed failed", "error", err)
		os.Exit(1)
	}

	// Parse the public URL once so handlers can reuse it.
	publicURL, err := url.Parse(cfg.SchlassPublicURL)
	if err != nil {
		slog.Error("failed to parse SCHLASS_PUBLIC_URL", "error", err)
		os.Exit(1)
	}

	// Wire up the admin endpoints that manage OIDC clients (create, rotate secret, delete, etc).
	clientStore := clients.NewStore()
	clientsHandler := clients.NewHandler(pool, valkeyClient, clientStore, auditStore, publicURL)

	// Optional: set up the "have I been pwned" check that blocks known breached passwords.
	// Left as nil if the feature is turned off.
	var hibpChecker *crypto.HIBPChecker
	if cfg.HIBPEnabled {
		hibpChecker = &crypto.HIBPChecker{
			Endpoint:   cfg.HIBPEndpoint,
			HTTPClient: &http.Client{Timeout: time.Duration(cfg.HIBPTimeoutMS) * time.Millisecond},
		}
	}

	// Build the router: every URL the app responds to, wired to its handler.
	h, err := server.BuildRouter(server.RouterDeps{
		Cfg:                    cfg,
		Pool:                   pool,
		ValkeyClient:           valkeyClient,
		ConfigStore:            configStore,
		UserStore:              userStore,
		RecoveryCodeStore:      recoveryCodeStore,
		AuditStore:             auditStore,
		InstanceConfig:         instanceConfig,
		LoginRateLimit:         cfg.LoginRateLimit,
		MfaChallengeRateLimit:  cfg.MfaChallengeRateLimit,
		PasswordResetRateLimit: cfg.PasswordResetRateLimit,
		AuthorizeRateLimit:     cfg.AuthorizeRateLimit,
		UserinfoRateLimit:      cfg.UserinfoRateLimit,
		TokenRateLimit:         cfg.TokenRateLimit,
		ClientsHandler:         clientsHandler,
		HIBPChecker:            hibpChecker,
	})
	if err != nil {
		slog.Error("failed to build router", "error", err)
		os.Exit(1)
	}

	// Configure the HTTP server: port to listen on, and how long a single request is allowed to take.
	httpServer := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      h,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start the server in the background so we can keep listening for shutdown signals down below.
	errChan := make(chan error, 1)
	go func() {
		slog.Info("server starting", "port", cfg.Port)
		errChan <- httpServer.ListenAndServe()
	}()

	// Block here until either the OS asks us to stop (Ctrl-C, docker stop) or the server itself crashes.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		slog.Info("shutdown signal received", "signal", sig)
	case err := <-errChan:
		slog.Error("server error", "error", err)
	}

	// Stop accepting new requests and give in-flight ones up to 30s to finish before forcing exit.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("forced shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("server stopped gracefully")
}
