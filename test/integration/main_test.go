//go:build integration

package integration

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/abdo75/Schlass/internal/database"
)

// TestMain boots one pgContainer + one valkeyContainer, runs the migration
// chain once, and caches the pristine instance_config rows into an unlogged
// snapshot table that resetState (in testutil.go) re-applies between tests.
// Each TestXxx still gets full state isolation via TRUNCATE + Valkey FLUSHDB
// inside NewTestEnv; the container lifecycle is just amortised.
func TestMain(m *testing.M) {
	ctx := context.Background()

	pgContainer, err := tcpostgres.Run(ctx,
		"postgres:18",
		tcpostgres.WithDatabase("schlass_test"),
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
		log.Fatalf("TestMain: start postgres: %v", err)
	}
	sharedPGContainer = pgContainer

	pgHost, _ := pgContainer.Host(ctx)
	pgPort, _ := pgContainer.MappedPort(ctx, "5432")
	sharedMigrConnString = fmt.Sprintf("postgres://schlass_migrations:schlass_migrations@%s:%s/schlass_test?sslmode=disable", pgHost, pgPort.Port())
	sharedAppConnString = fmt.Sprintf("postgres://schlass_app:schlass_app@%s:%s/schlass_test?sslmode=disable", pgHost, pgPort.Port())
	sharedPurgeConnString = fmt.Sprintf("postgres://audit_purge_runner:audit_purge_runner@%s:%s/schlass_test?sslmode=disable", pgHost, pgPort.Port())

	if err := database.RunMigrations(sharedMigrConnString); err != nil {
		_ = pgContainer.Terminate(ctx)
		log.Fatalf("TestMain: run migrations: %v", err)
	}

	// Capture the pristine instance_config as an unlogged snapshot table.
	// resetState() uses this to restore defaults between tests without
	// hard-coding keys that a future migration might add.
	if err := createInstanceConfigSnapshot(ctx); err != nil {
		_ = pgContainer.Terminate(ctx)
		log.Fatalf("TestMain: snapshot instance_config: %v", err)
	}

	valkeyContainer, err := tcredis.Run(ctx, "valkey/valkey:9")
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		log.Fatalf("TestMain: start valkey: %v", err)
	}
	sharedValkeyContainer = valkeyContainer

	valkeyHost, _ := valkeyContainer.Host(ctx)
	valkeyPort, _ := valkeyContainer.MappedPort(ctx, "6379")
	sharedValkeyAddr = fmt.Sprintf("%s:%s", valkeyHost, valkeyPort.Port())

	code := m.Run()

	_ = pgContainer.Terminate(ctx)
	_ = valkeyContainer.Terminate(ctx)
	os.Exit(code)
}

// createInstanceConfigSnapshot copies the pristine instance_config into an
// unlogged table that lives for the whole test run. TRUNCATE + re-INSERT
// from this snapshot is how resetState restores config defaults between
// tests — future migrations that add new config keys are picked up
// automatically without touching this file.
func createInstanceConfigSnapshot(ctx context.Context) error {
	pool, err := database.NewPool(ctx, sharedMigrConnString)
	if err != nil {
		return fmt.Errorf("connect for snapshot: %w", err)
	}
	defer pool.Close()

	_, err = pool.Exec(ctx, `
		DROP TABLE IF EXISTS _instance_config_snapshot;
		CREATE UNLOGGED TABLE _instance_config_snapshot AS
			SELECT * FROM instance_config;
	`)
	return err
}
