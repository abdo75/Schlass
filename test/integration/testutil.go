//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/abdo75/Schlass/internal/config"
	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/database"
	"github.com/abdo75/Schlass/internal/handler"
	"github.com/abdo75/Schlass/internal/server"
	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/store"
)

type TestEnv struct {
	Pool              *pgxpool.Pool
	MigrationsPool    *pgxpool.Pool
	ValkeyClient      *redis.Client
	Valkey            *redis.Client // alias for ValkeyClient — MFA tests use this spelling
	AppConnString     string
	MigrConnString    string
	Router            http.Handler
	Cfg               *config.Config
	UserStore         *store.UserStore
	RecoveryCodeStore *store.RecoveryCodeStore
	SessionStore      session.Store
}

// Cleanup is a no-op — t.Cleanup registered in NewTestEnv handles teardown.
// Kept as a method so tests using `defer env.Cleanup()` compile cleanly.
func (e *TestEnv) Cleanup() {}

// Close is an alias for Cleanup — tests may use either spelling.
func (e *TestEnv) Close() {}

// NewTestEnv returns a TestEnv wired to the shared PG + Valkey containers
// booted once in TestMain. Each call performs a full state reset — TRUNCATE
// of all app-writable tables, restore of instance_config from the snapshot
// captured at migration time, and FLUSHDB on Valkey — so tests stay
// independent even though they share the underlying containers.
func NewTestEnv(t *testing.T) *TestEnv {
	t.Helper()
	ctx := context.Background()

	if sharedAppConnString == "" {
		t.Fatal("NewTestEnv called before TestMain set up shared containers — missing //go:build integration tag?")
	}

	pool, err := database.NewPool(ctx, sharedAppConnString)
	if err != nil {
		t.Fatalf("connect as app role: %v", err)
	}
	migrPool, err := database.NewPool(ctx, sharedMigrConnString)
	if err != nil {
		pool.Close()
		t.Fatalf("connect as migrations role: %v", err)
	}

	resetState(t, migrPool)

	valkeyClient := redis.NewClient(&redis.Options{Addr: sharedValkeyAddr})
	if err := valkeyClient.Ping(ctx).Err(); err != nil {
		pool.Close()
		migrPool.Close()
		t.Fatalf("ping shared valkey: %v", err)
	}
	if err := valkeyClient.FlushDB(ctx).Err(); err != nil {
		pool.Close()
		migrPool.Close()
		_ = valkeyClient.Close()
		t.Fatalf("flushdb shared valkey: %v", err)
	}

	// Deterministic test encryption key (32 bytes of zeros). Tests that need
	// a real key should inject their own.
	cfg := &config.Config{
		DatabaseURL:           sharedAppConnString,
		MigrationsDatabaseURL: sharedMigrConnString,
		ValkeyURL:             "redis://" + sharedValkeyAddr,
		EncryptionKey:         make([]byte, 32),
		Port:                  "3000",
		SchlassPublicURL:      "http://localhost:3000",
	}

	env := &TestEnv{
		Pool:              pool,
		MigrationsPool:    migrPool,
		ValkeyClient:      valkeyClient,
		Valkey:            valkeyClient,
		AppConnString:     sharedAppConnString,
		MigrConnString:    sharedMigrConnString,
		Cfg:               cfg,
		UserStore:         store.NewUserStore(),
		RecoveryCodeStore: store.NewRecoveryCodeStore(),
		SessionStore:      session.NewValkeyStore(valkeyClient, 24*time.Hour),
	}

	router, err := server.BuildRouter(env.BuildDeps())
	if err != nil {
		pool.Close()
		migrPool.Close()
		_ = valkeyClient.Close()
		t.Fatalf("build router: %v", err)
	}
	env.Router = router

	t.Cleanup(func() {
		pool.Close()
		migrPool.Close()
		_ = valkeyClient.Close()
	})

	return env
}

// resetState returns the shared PG to a pristine post-migration state: all
// app-writable tables truncated with identities reset, and instance_config
// restored from the TestMain-captured snapshot. Uses the migrations role
// because audit_logs' RLS policy only grants SELECT + INSERT to the app
// role; TRUNCATE requires owner-level access.
func resetState(t *testing.T, migrPool *pgxpool.Pool) {
	t.Helper()
	_, err := migrPool.Exec(context.Background(), `
		TRUNCATE TABLE
			audit_logs,
			totp_recovery_codes,
			users,
			clients,
			scopes,
			authorization_codes,
			signing_keys,
			instance_config
		RESTART IDENTITY CASCADE;
		INSERT INTO instance_config (key, value, updated_at)
			SELECT key, value, updated_at FROM _instance_config_snapshot;
	`)
	if err != nil {
		t.Fatalf("resetState: %v", err)
	}
}

// setupIntegrationEnv is a thin alias for NewTestEnv. Provided because the
// Sprint 2 gated tests (login_test.go, auth_middleware_test.go) were written
// against this name before NewTestEnv existed.
func setupIntegrationEnv(t *testing.T) *TestEnv {
	return NewTestEnv(t)
}

// BuildDeps returns a RouterDeps snapshot of the current test environment.
// Used internally by NewTestEnv and externally by WithFakeAuditStore when it
// needs to rebuild the router with a swapped dependency.
func (e *TestEnv) BuildDeps() server.RouterDeps {
	configStore := store.NewConfigStore()
	auditStore := store.NewAuditStore()
	clientStore := store.NewClientStore()
	publicURL, _ := url.Parse(e.Cfg.SchlassPublicURL) // always valid — set from test constants
	clientsHandler := handler.NewClientsHandler(e.Pool, e.ValkeyClient, clientStore, auditStore, publicURL)
	return server.RouterDeps{
		Cfg:               e.Cfg,
		Pool:              e.Pool,
		ValkeyClient:      e.ValkeyClient,
		ConfigStore:       configStore,
		UserStore:         store.NewUserStore(),
		RecoveryCodeStore: store.NewRecoveryCodeStore(),
		AuditStore:        auditStore,
		ConfigService:     config.NewConfigService(configStore, e.Cfg.EncryptionKey),
		// Tests drive many login attempts from the same virtual client IP
		// (httptest uses 192.0.2.1 for every request). Raise the login
		// rate-limit cap so the production 5/min guard doesn't mask the
		// application-level lockout semantics we're trying to test.
		LoginRateLimit: 10000,
		// Same rationale for MFA challenge: integration tests may fire many
		// challenge requests from the same virtual IP without hitting the
		// production 5/min guard.
		MfaChallengeRateLimit: 10000,
		ClientsHandler:        clientsHandler,
	}
}

// SeedAdmin creates a super_admin user with the given email and password,
// using the real crypto.HashPassword so the password is verifiable via the
// login handler. Returns the new user's ID.
func (e *TestEnv) SeedAdmin(t *testing.T, email, password string) uuid.UUID {
	t.Helper()
	hash, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	us := store.NewUserStore()
	id, err := us.Create(context.Background(), e.Pool, email, hash, "super_admin", false)
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	return id
}

// LoginAsAdmin performs a real POST /api/login against the test router and
// returns the schlass_session cookie set on the response. Fails the test if
// the login did not succeed or the cookie was not set.
//
// MFA is temporarily disabled for the duration of the login so this helper
// always exercises the legacy 200-path. Callers that want to test MFA-gated
// login should drive the full flow themselves rather than using this helper.
func (e *TestEnv) LoginAsAdmin(t *testing.T, email, password string) *http.Cookie {
	t.Helper()

	// Disable MFA so we always get a session cookie on the first request.
	if _, err := e.Pool.Exec(context.Background(), `UPDATE instance_config SET value = 'false' WHERE key = 'mfa_required'`); err != nil {
		t.Fatalf("LoginAsAdmin: disable mfa: %v", err)
	}
	// No cleanup needed for mfa_required — the next test's resetState restores
	// instance_config from the snapshot, which has mfa_required = 'true'.

	body := bytes.NewBufferString(`{"email":"` + email + `","password":"` + password + `"}`)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	e.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "schlass_session" {
			return c
		}
	}
	t.Fatal("no session cookie in login response")
	return nil
}

// CaptureLogs installs a JSON slog handler writing to a returned buffer for
// the duration of the test, restoring the original default on cleanup.
func (e *TestEnv) CaptureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(original) })
	return &buf
}

// failingAuditStore satisfies handler.AuditLogger by returning whatever fn
// returns on every Log call. Used by WithFakeAuditStore to exercise the
// "audit failure rolls back the login tx" contract.
type failingAuditStore struct {
	fn func() error
}

func (f *failingAuditStore) Log(_ context.Context, _ database.Querier, _ store.AuditEntry) error {
	return f.fn()
}

// PseudonymizeUser satisfies handler.AuditLogger. Fake returns 0 rows with
// no error — tests that drive the pseudonymize path use the real store.
func (f *failingAuditStore) PseudonymizeUser(_ context.Context, _ database.Querier, _ uuid.UUID) (int, error) {
	return 0, nil
}

// Compile-time proof that failingAuditStore satisfies handler.AuditLogger.
var _ handler.AuditLogger = (*failingAuditStore)(nil)

// WithFakeAuditStore rebuilds the router with an audit store whose Log method
// always returns fn(). The original router is restored via t.Cleanup so the
// swap is scoped to the current test.
func (e *TestEnv) WithFakeAuditStore(t *testing.T, fn func() error) {
	t.Helper()
	original := e.Router
	deps := e.BuildDeps()
	deps.AuditStore = &failingAuditStore{fn: fn}
	newRouter, err := server.BuildRouter(deps)
	if err != nil {
		t.Fatalf("rebuild router with fake audit store: %v", err)
	}
	e.Router = newRouter
	t.Cleanup(func() { e.Router = original })
}

// WithBrokenValkey rebuilds the router with a Valkey client pointed at a
// closed local port so every redis call fails with connection-refused.
// Replaces the old StopValkey/StartValkey pattern, which couldn't coexist
// with a shared container — stopping the singleton Valkey would break every
// other test in the run. The broken-client approach is per-router-instance
// and naturally scoped via t.Cleanup.
//
// Used by TestAuthMiddleware_ValkeyError_Returns503 to exercise the 503
// transient-Valkey-error path in middleware.Auth.
func (e *TestEnv) WithBrokenValkey(t *testing.T) {
	t.Helper()
	original := e.Router
	deps := e.BuildDeps()
	deps.ValkeyClient = redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1", // reserved/unassigned — connection refused
		MaxRetries:  -1,             // no retries — fail fast
		DialTimeout: 100 * time.Millisecond,
	})
	newRouter, err := server.BuildRouter(deps)
	if err != nil {
		t.Fatalf("rebuild router with broken valkey: %v", err)
	}
	e.Router = newRouter
	t.Cleanup(func() { e.Router = original })
}

// CompleteSetup calls POST /api/setup to initialise the instance with the
// given admin email and password. Fails the test if setup does not return 200.
func (e *TestEnv) CompleteSetup(t *testing.T, email, password string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"email":            email,
		"password":         password,
		"confirm_password": password,
		"instance_name":    "Test Corp",
	})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("CompleteSetup: POST /api/setup returned %d: %s", rec.Code, rec.Body.String())
	}
}

// GetUserIDByEmail looks up the UUID for the user with the given email address.
// Fails the test if the user is not found.
func (e *TestEnv) GetUserIDByEmail(t *testing.T, email string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := e.Pool.QueryRow(context.Background(),
		`SELECT id FROM users WHERE email = $1`, email,
	).Scan(&id); err != nil {
		t.Fatalf("GetUserIDByEmail(%q): %v", email, err)
	}
	return id
}

// DirectCreateUser inserts a user row directly (bypassing the API) for tests
// that need a second user. Returns the UUID. Not a substitute for integration
// testing POST /api/users — use only for test setup.
func (e *TestEnv) DirectCreateUser(t *testing.T, email, role string) uuid.UUID {
	t.Helper()
	hash, err := crypto.HashPassword("test-placeholder-password")
	if err != nil {
		t.Fatalf("DirectCreateUser: hash password: %v", err)
	}
	id, err := e.UserStore.Create(context.Background(), e.Pool, strings.ToLower(email), hash, role, false)
	if err != nil {
		t.Fatalf("DirectCreateUser: %v", err)
	}
	return id
}

// DirectCreateSession creates a Valkey session for the given user without
// going through POST /api/login. Returns a *http.Cookie ready to attach to
// test requests.
func (e *TestEnv) DirectCreateSession(t *testing.T, userID uuid.UUID) *http.Cookie {
	t.Helper()
	token, err := e.SessionStore.Create(context.Background(), userID.String(), "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("DirectCreateSession: %v", err)
	}
	return &http.Cookie{Name: "schlass_session", Value: token}
}
