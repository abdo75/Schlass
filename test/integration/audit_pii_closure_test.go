//go:build integration

// Tests for milestone M2 (REQ-AUD-011/030/031): actor_email column is
// gone, ip_address is renamed + coarsened, the pseudonymization
// function nulls actor_id + writes metadata.pseudonymized_at.
package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/abdo75/Schlass/internal/audit"
)

// TestAuditPIIClosure_ActorEmailColumnDropped asserts the column is
// gone from the live schema. Anything that still SELECTs actor_email
// will fail at parse time, so this is the static guarantee.
func TestAuditPIIClosure_ActorEmailColumnDropped(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	var n int
	if err := env.Pool.QueryRow(context.Background(), `
		SELECT count(*) FROM information_schema.columns
		 WHERE table_schema = 'public'
		   AND table_name = 'audit_logs'
		   AND column_name = 'actor_email'
	`).Scan(&n); err != nil {
		t.Fatalf("information_schema lookup: %v", err)
	}
	if n != 0 {
		t.Fatalf("audit_logs.actor_email still present (count = %d) — M2 migration regressed", n)
	}
}

// TestAuditPIIClosure_ClientIPColumnRenamed asserts the rename half of
// REQ-AUD-031: ip_address -> client_ip_coarse.
func TestAuditPIIClosure_ClientIPColumnRenamed(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	var dataType string
	if err := env.Pool.QueryRow(context.Background(), `
		SELECT data_type FROM information_schema.columns
		 WHERE table_schema = 'public'
		   AND table_name = 'audit_logs'
		   AND column_name = 'client_ip_coarse'
	`).Scan(&dataType); err != nil {
		t.Fatalf("client_ip_coarse missing: %v", err)
	}
	if dataType != "inet" {
		t.Fatalf("client_ip_coarse data_type = %q, want %q", dataType, "inet")
	}

	// And the old name must be gone.
	var n int
	if err := env.Pool.QueryRow(context.Background(), `
		SELECT count(*) FROM information_schema.columns
		 WHERE table_schema = 'public'
		   AND table_name = 'audit_logs'
		   AND column_name = 'ip_address'
	`).Scan(&n); err != nil {
		t.Fatalf("information_schema lookup: %v", err)
	}
	if n != 0 {
		t.Fatalf("audit_logs.ip_address still present after M2 rename")
	}
}

// TestAuditPIIClosure_HistoricalIPsCoarsened asserts that any v4 row
// surviving the migration has been masked to /24 (no host bits below).
func TestAuditPIIClosure_HistoricalIPsCoarsened(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	var leaked int
	if err := env.Pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_logs
		 WHERE family(client_ip_coarse) = 4 AND masklen(client_ip_coarse) > 24
	`).Scan(&leaked); err != nil {
		t.Fatalf("scan v4 leak count: %v", err)
	}
	if leaked != 0 {
		t.Fatalf("expected 0 v4 rows with />24 mask post-migration, got %d", leaked)
	}
	if err := env.Pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_logs
		 WHERE family(client_ip_coarse) = 6 AND masklen(client_ip_coarse) > 48
	`).Scan(&leaked); err != nil {
		t.Fatalf("scan v6 leak count: %v", err)
	}
	if leaked != 0 {
		t.Fatalf("expected 0 v6 rows with />48 mask post-migration, got %d", leaked)
	}
}

// TestAuditPIIClosure_EmitCoarsensV4 verifies the coarse IP mode masks
// IPv4 addresses to /24 at emit time.
func TestAuditPIIClosure_EmitCoarsensV4(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	store := audit.NewStoreWithIPMode(audit.IPModeCoarse)
	tx, err := env.Pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	actorID := uuid.New()
	if err := store.Emit(context.Background(), tx, audit.Event{
		EventType: "login.succeeded",
		Outcome:   "success",
		ActorID:   &actorID,
		IPAddress: "192.168.5.42",
	}); err != nil {
		t.Fatalf("emit: %v", err)
	}

	var got string
	if err := tx.QueryRow(context.Background(),
		`SELECT host(client_ip_coarse) FROM audit_logs WHERE actor_id = $1`, actorID,
	).Scan(&got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got != "192.168.5.0" {
		t.Fatalf("v4 coarse = %q, want %q", got, "192.168.5.0")
	}
}

// TestAuditPIIClosure_EmitCoarsensV6 verifies the coarse IP mode masks
// IPv6 addresses to /48.
func TestAuditPIIClosure_EmitCoarsensV6(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	store := audit.NewStoreWithIPMode(audit.IPModeCoarse)
	tx, err := env.Pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	actorID := uuid.New()
	if err := store.Emit(context.Background(), tx, audit.Event{
		EventType: "login.succeeded",
		Outcome:   "success",
		ActorID:   &actorID,
		IPAddress: "2001:db8::1234",
	}); err != nil {
		t.Fatalf("emit: %v", err)
	}

	var got string
	if err := tx.QueryRow(context.Background(),
		`SELECT host(client_ip_coarse) FROM audit_logs WHERE actor_id = $1`, actorID,
	).Scan(&got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	// Postgres canonicalizes "2001:db8::" as the host text representation.
	if got != "2001:db8::" {
		t.Fatalf("v6 coarse = %q, want %q", got, "2001:db8::")
	}
}

// TestAuditPIIClosure_EmitOffMode_DropsIP verifies IPModeOff stores
// NULL in client_ip_coarse and client_geo_coarse.
func TestAuditPIIClosure_EmitOffMode_DropsIP(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	store := audit.NewStoreWithIPMode(audit.IPModeOff)
	tx, err := env.Pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	actorID := uuid.New()
	if err := store.Emit(context.Background(), tx, audit.Event{
		EventType:       "login.succeeded",
		Outcome:         "success",
		ActorID:         &actorID,
		IPAddress:       "192.168.5.42",
		ClientGeoCoarse: "DE", // also stripped in off mode
	}); err != nil {
		t.Fatalf("emit: %v", err)
	}

	var ip, geo *string
	if err := tx.QueryRow(context.Background(),
		`SELECT client_ip_coarse::text, client_geo_coarse FROM audit_logs WHERE actor_id = $1`,
		actorID,
	).Scan(&ip, &geo); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if ip != nil {
		t.Fatalf("client_ip_coarse = %q, want NULL in off mode", *ip)
	}
	if geo != nil {
		t.Fatalf("client_geo_coarse = %q, want NULL in off mode", *geo)
	}
}

// TestAuditPIIClosure_EmitCountryMode_NoProvider verifies IPModeCountry
// without a wired provider stores NULL ip + the documented sentinel in
// client_geo_coarse.
func TestAuditPIIClosure_EmitCountryMode_NoProvider(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	store := audit.NewStoreWithIPMode(audit.IPModeCountry)
	tx, err := env.Pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	actorID := uuid.New()
	if err := store.Emit(context.Background(), tx, audit.Event{
		EventType: "login.succeeded",
		Outcome:   "success",
		ActorID:   &actorID,
		IPAddress: "192.168.5.42",
	}); err != nil {
		t.Fatalf("emit: %v", err)
	}

	var ip, geo *string
	if err := tx.QueryRow(context.Background(),
		`SELECT client_ip_coarse::text, client_geo_coarse FROM audit_logs WHERE actor_id = $1`,
		actorID,
	).Scan(&ip, &geo); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if ip != nil {
		t.Fatalf("client_ip_coarse = %q, want NULL in country mode", *ip)
	}
	if geo == nil || *geo != "country_lookup_unconfigured" {
		t.Fatalf("client_geo_coarse = %v, want %q", geo, "country_lookup_unconfigured")
	}
}

// TestAuditPIIClosure_PseudonymizeFunctionNullsActorAndStampsMetadata
// asserts the M2 contract: the SECURITY DEFINER function nulls actor_id
// and writes metadata.pseudonymized_at instead of touching actor_email
// (which is gone).
func TestAuditPIIClosure_PseudonymizeFunctionNullsActorAndStampsMetadata(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	ctx := context.Background()
	userID := env.DirectCreateUser(t, "pseudo@example.com", "user")

	// Seed an audit row with this user as actor.
	store := audit.NewStore()
	tx, err := env.Pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin seed: %v", err)
	}
	if err := store.Emit(ctx, tx, audit.Event{
		EventType: "login.succeeded",
		Outcome:   "success",
		ActorID:   &userID,
		IPAddress: "203.0.113.7",
	}); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("seed emit: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("seed commit: %v", err)
	}

	// Run the SECURITY DEFINER function.
	var rowsTouched int
	if err := env.Pool.QueryRow(ctx, `SELECT audit_log_pseudonymize_user($1)`, userID).Scan(&rowsTouched); err != nil {
		t.Fatalf("pseudonymize: %v", err)
	}
	if rowsTouched < 1 {
		t.Fatalf("rows_touched = %d, want >= 1", rowsTouched)
	}

	// Row now has actor_id NULL + metadata.pseudonymized_at populated.
	var actor *string
	var pseudoAt *string
	if err := env.Pool.QueryRow(ctx,
		`SELECT actor_id::text, metadata->>'pseudonymized_at' FROM audit_logs
		 WHERE event_type = 'login.succeeded'
		 ORDER BY created_at DESC LIMIT 1`,
	).Scan(&actor, &pseudoAt); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if actor != nil {
		t.Fatalf("actor_id = %q, want NULL", *actor)
	}
	if pseudoAt == nil || *pseudoAt == "" {
		t.Fatal("metadata.pseudonymized_at not set")
	}

	// Second invocation is a no-op (the WHERE clause filters out
	// already-pseudonymized rows via the metadata marker).
	var second int
	if err := env.Pool.QueryRow(ctx, `SELECT audit_log_pseudonymize_user($1)`, userID).Scan(&second); err != nil {
		t.Fatalf("second pseudonymize: %v", err)
	}
	if second != 0 {
		t.Fatalf("second pseudonymize touched %d rows, want 0", second)
	}
}

// TestAuditPIIClosure_ClientIPModeConfigKeySeeded asserts the migration
// seeds the audit.client_ip_mode key with the default value.
func TestAuditPIIClosure_ClientIPModeConfigKeySeeded(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	var raw string
	if err := env.Pool.QueryRow(context.Background(),
		`SELECT value::text FROM instance_config WHERE key = 'audit.client_ip_mode'`,
	).Scan(&raw); err != nil {
		t.Fatalf("missing audit.client_ip_mode key: %v", err)
	}
	if raw != `"coarse"` {
		t.Fatalf("seeded audit.client_ip_mode = %q, want %q", raw, `"coarse"`)
	}
}
