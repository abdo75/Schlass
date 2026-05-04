//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/abdo75/Schlass/internal/database"
)

func TestMigrationsUpDownUp(t *testing.T) {
	ctx := context.Background()

	pgContainer, err := tcpostgres.Run(ctx,
		"postgres:18",
		tcpostgres.WithDatabase("schlass_migtest"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("postgres"),
		tcpostgres.WithInitScripts("../../scripts/init-test-db.sh"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("failed to start postgres: %v", err)
	}
	t.Cleanup(func() { _ = pgContainer.Terminate(ctx) })

	pgHost, _ := pgContainer.Host(ctx)
	pgPort, _ := pgContainer.MappedPort(ctx, "5432")
	connString := fmt.Sprintf("postgres://schlass_migrations:schlass_migrations@%s:%s/schlass_migtest?sslmode=disable", pgHost, pgPort.Port())

	// Up — should apply all migrations
	if err := database.RunMigrations(connString); err != nil {
		t.Fatalf("first migration up failed: %v", err)
	}

	// M5-specific gate: roll back the purge role + runner role pair and
	// re-apply them cleanly before exercising the full down/up cycle.
	if err := database.RunMigrationSteps(connString, -2); err != nil {
		t.Fatalf("migration down 2 failed: %v", err)
	}
	if err := database.RunMigrations(connString); err != nil {
		t.Fatalf("migration re-up after down 2 failed: %v", err)
	}

	// Down — should roll back all migrations
	if err := database.RunMigrationsDown(connString); err != nil {
		t.Fatalf("migration down failed: %v", err)
	}

	// Up again — should re-apply cleanly
	if err := database.RunMigrations(connString); err != nil {
		t.Fatalf("second migration up failed: %v", err)
	}
}

func TestMigration000008CreatesPartitionsForExistingOldRows(t *testing.T) {
	ctx := context.Background()

	pgContainer, err := tcpostgres.Run(ctx,
		"postgres:18",
		tcpostgres.WithDatabase("schlass_oldrows"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("postgres"),
		tcpostgres.WithInitScripts("../../scripts/init-test-db.sh"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("failed to start postgres: %v", err)
	}
	t.Cleanup(func() { _ = pgContainer.Terminate(ctx) })

	pgHost, _ := pgContainer.Host(ctx)
	pgPort, _ := pgContainer.MappedPort(ctx, "5432")
	connString := fmt.Sprintf("postgres://schlass_migrations:schlass_migrations@%s:%s/schlass_oldrows?sslmode=disable", pgHost, pgPort.Port())

	if err := database.RunMigrationSteps(connString, 7); err != nil {
		t.Fatalf("migration up to 000007 failed: %v", err)
	}
	pool, err := database.NewPool(ctx, connString)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	oldTS := time.Now().UTC().AddDate(0, -18, 0)
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_logs (
			id, event_type, outcome, event_timestamp, actor_type, tenant_id,
			source_service, sequence_no, prev_hash, row_hash
		)
		VALUES (
			gen_random_uuid(), 'login.succeeded', 'success', $1, 'system',
			'00000000-0000-0000-0000-000000000000', 'auth', 1, NULL,
			digest('legacy:' || gen_random_uuid()::text, 'sha256')
		)`, oldTS); err != nil {
		t.Fatalf("insert old audit row before 000008: %v", err)
	}
	if err := database.RunMigrations(connString); err != nil {
		t.Fatalf("migration through 000008+ failed: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_logs WHERE event_timestamp < now() - interval '13 months'`).Scan(&count); err != nil {
		t.Fatalf("count old rows after migration: %v", err)
	}
	if count != 1 {
		t.Fatalf("old rows after migration = %d, want 1", count)
	}
}
