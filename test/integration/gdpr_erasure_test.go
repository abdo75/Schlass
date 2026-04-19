//go:build integration

package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/abdo75/Schlass/internal/crypto"
)

// TestGDPR_ActorEmailPseudonymizedOnDelete walks the full GDPR Art. 17 path:
// admin creates U, U performs an audit-emitting action (login), admin deletes
// U, the original audit row's actor_email is now 'deleted:<uuid>' instead of
// U's real email. The parallel row recording the admin's delete action keeps
// the admin's actor_email (it's attributable to the admin, not the victim).
func TestGDPR_ActorEmailPseudonymizedOnDelete(t *testing.T) {
	ctx := t.Context()
	env := NewTestEnv(t)

	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42Battery")
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42Battery")

	const victimEmail = "erase-me@example.com"
	const victimPassword = "VictimPass42Battery"
	hash, err := crypto.HashPassword(victimPassword)
	if err != nil {
		t.Fatalf("hash victim password: %v", err)
	}
	// force_password_change=false so the login-succeeded branch is the
	// straight legacy path (no MFA per LoginAsAdmin helper).
	if _, err := env.Pool.Exec(ctx,
		`INSERT INTO users (email, password_hash, role, force_password_change)
		 VALUES ($1, $2, 'user', false)`, victimEmail, hash); err != nil {
		t.Fatalf("seed victim: %v", err)
	}
	victimID := userIDByEmail(t, env, victimEmail)

	// Victim logs in — writes a login.succeeded audit row with
	// actor_email=victimEmail and actor_id=victimID.
	_ = env.LoginAsAdmin(t, victimEmail, victimPassword)

	// Sanity: pre-delete, the victim's login audit row carries their real email.
	var preEmail string
	if err := env.Pool.QueryRow(ctx,
		`SELECT actor_email FROM audit_logs
		 WHERE actor_id = $1 AND event_type = 'login.succeeded'
		 ORDER BY created_at DESC LIMIT 1`, victimID,
	).Scan(&preEmail); err != nil {
		t.Fatalf("pre-delete login audit row missing: %v", err)
	}
	if preEmail != victimEmail {
		t.Fatalf("pre-delete actor_email=%q, want %q", preEmail, victimEmail)
	}

	// Admin deletes the victim.
	req := httptest.NewRequestWithContext(ctx, "DELETE", "/api/users/"+victimID, nil)
	req.AddCookie(adminCookie)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: got %d, want 204 — body=%s", rec.Code, rec.Body.String())
	}

	// The original login.succeeded row now has actor_email = 'deleted:<uuid>'.
	var scrubbedEmail string
	if err := env.Pool.QueryRow(ctx,
		`SELECT actor_email FROM audit_logs
		 WHERE actor_id = $1 AND event_type = 'login.succeeded'
		 ORDER BY created_at DESC LIMIT 1`, victimID,
	).Scan(&scrubbedEmail); err != nil {
		t.Fatalf("query scrubbed row: %v", err)
	}
	want := "deleted:" + victimID
	if scrubbedEmail != want {
		t.Fatalf("actor_email=%q, want %q", scrubbedEmail, want)
	}

	// The user.deleted row is attributable to the admin — must NOT be scrubbed.
	var adminEmailAfter string
	if err := env.Pool.QueryRow(ctx,
		`SELECT actor_email FROM audit_logs
		 WHERE target_id = $1 AND event_type = 'user.deleted'
		 ORDER BY created_at DESC LIMIT 1`, victimID,
	).Scan(&adminEmailAfter); err != nil {
		t.Fatalf("query user.deleted row: %v", err)
	}
	if adminEmailAfter != "admin@example.com" {
		t.Fatalf("user.deleted actor_email=%q, want admin@example.com (must not be scrubbed)", adminEmailAfter)
	}

	// The user.audit_pseudonymized audit row must be present, actor_email
	// is the admin, and rows_updated > 0 in metadata.
	var pseudoActor string
	var rowsUpdated int
	if err := env.Pool.QueryRow(ctx,
		`SELECT actor_email, COALESCE((metadata->>'rows_updated')::int, 0)
		 FROM audit_logs
		 WHERE target_id = $1 AND event_type = 'user.audit_pseudonymized'
		 ORDER BY created_at DESC LIMIT 1`, victimID,
	).Scan(&pseudoActor, &rowsUpdated); err != nil {
		t.Fatalf("query user.audit_pseudonymized: %v", err)
	}
	if pseudoActor != "admin@example.com" {
		t.Fatalf("user.audit_pseudonymized actor_email=%q, want admin@example.com", pseudoActor)
	}
	if rowsUpdated < 1 {
		t.Fatalf("user.audit_pseudonymized rows_updated=%d, want >= 1", rowsUpdated)
	}

	// Regression guard: schlass_app role must NOT be able to UPDATE audit_logs
	// directly. The SECURITY DEFINER function is the only sanctioned path.
	assertAppRoleCannotUpdateAuditLogs(t, env)
}

// TestGDPR_PseudonymizeIdempotent: calling the function twice on the same
// user returns 0 rows on the second call (IS DISTINCT FROM guard).
func TestGDPR_PseudonymizeIdempotent(t *testing.T) {
	ctx := t.Context()
	env := NewTestEnv(t)

	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42Battery")
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42Battery")

	const victimEmail = "idem@example.com"
	const victimPassword = "IdempotentPass42Battery"
	hash, err := crypto.HashPassword(victimPassword)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := env.Pool.Exec(ctx,
		`INSERT INTO users (email, password_hash, role, force_password_change)
		 VALUES ($1, $2, 'user', false)`, victimEmail, hash); err != nil {
		t.Fatalf("seed victim: %v", err)
	}
	victimID := userIDByEmail(t, env, victimEmail)
	_ = env.LoginAsAdmin(t, victimEmail, victimPassword)

	req := httptest.NewRequestWithContext(ctx, "DELETE", "/api/users/"+victimID, nil)
	req.AddCookie(adminCookie)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: got %d — body=%s", rec.Code, rec.Body.String())
	}

	// Second invocation — call the SQL function directly. The IS DISTINCT FROM
	// guard in migration 000018 must make this a no-op.
	qctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var rows int
	if err := env.Pool.QueryRow(qctx,
		`SELECT audit_log_pseudonymize_user($1)`, victimID,
	).Scan(&rows); err != nil {
		t.Fatalf("second pseudonymize call: %v", err)
	}
	if rows != 0 {
		t.Fatalf("second call returned %d rows, want 0 (IS DISTINCT FROM guard should make it a no-op)", rows)
	}
}

// assertAppRoleCannotUpdateAuditLogs opens a fresh schlass_app connection and
// asserts that a direct UPDATE against audit_logs fails with 42501
// (insufficient_privilege). This is the regression guard for the append-only
// compliance claim — the SECURITY DEFINER function is the only sanctioned
// mutation path.
func assertAppRoleCannotUpdateAuditLogs(t *testing.T, env *TestEnv) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// env.AppConnString is already the schlass_app DSN (see main_test.go).
	if !strings.Contains(env.AppConnString, "schlass_app") {
		t.Fatalf("AppConnString does not reference schlass_app role: %s", env.AppConnString)
	}
	conn, err := pgx.Connect(ctx, env.AppConnString)
	if err != nil {
		t.Fatalf("connect as schlass_app: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	_, err = conn.Exec(ctx,
		`UPDATE audit_logs SET actor_email = 'x' WHERE id = '00000000-0000-0000-0000-000000000000'`)
	if err == nil {
		t.Fatal("schlass_app unexpectedly has UPDATE on audit_logs — compliance regression")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("expected 42501 insufficient_privilege, got: %v", err)
	}
}
