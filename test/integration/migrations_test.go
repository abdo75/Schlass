package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/schlass/schlass/internal/database"
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

	// Down — should roll back all migrations
	if err := database.RunMigrationsDown(connString); err != nil {
		t.Fatalf("migration down failed: %v", err)
	}

	// Up again — should re-apply cleanly
	if err := database.RunMigrations(connString); err != nil {
		t.Fatalf("second migration up failed: %v", err)
	}
}
