package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/schlass/schlass/internal/database"
)

type TestEnv struct {
	Pool            *pgxpool.Pool
	MigrationsPool  *pgxpool.Pool
	ValkeyClient    *redis.Client
	AppConnString   string
	MigrConnString  string
	pgContainer     testcontainers.Container
	valkeyContainer testcontainers.Container
}

func NewTestEnv(t *testing.T) *TestEnv {
	t.Helper()
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
		t.Fatalf("failed to start postgres: %v", err)
	}

	pgHost, _ := pgContainer.Host(ctx)
	pgPort, _ := pgContainer.MappedPort(ctx, "5432")

	migrConnString := fmt.Sprintf("postgres://schlass_migrations:schlass_migrations@%s:%s/schlass_test?sslmode=disable", pgHost, pgPort.Port())
	appConnString := fmt.Sprintf("postgres://schlass_app:schlass_app@%s:%s/schlass_test?sslmode=disable", pgHost, pgPort.Port())

	if err := database.RunMigrations(migrConnString); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	pool, err := database.NewPool(ctx, appConnString)
	if err != nil {
		t.Fatalf("failed to connect as app role: %v", err)
	}

	migrPool, err := database.NewPool(ctx, migrConnString)
	if err != nil {
		t.Fatalf("failed to connect as migrations role: %v", err)
	}

	valkeyContainer, err := tcredis.Run(ctx, "valkey/valkey:9")
	if err != nil {
		t.Fatalf("failed to start valkey: %v", err)
	}

	valkeyHost, _ := valkeyContainer.Host(ctx)
	valkeyPort, _ := valkeyContainer.MappedPort(ctx, "6379")
	valkeyAddr := fmt.Sprintf("%s:%s", valkeyHost, valkeyPort.Port())

	valkeyClient := redis.NewClient(&redis.Options{Addr: valkeyAddr})
	if err := valkeyClient.Ping(ctx).Err(); err != nil {
		t.Fatalf("failed to ping valkey: %v", err)
	}

	env := &TestEnv{
		Pool:            pool,
		MigrationsPool:  migrPool,
		ValkeyClient:    valkeyClient,
		AppConnString:   appConnString,
		MigrConnString:  migrConnString,
		pgContainer:     pgContainer,
		valkeyContainer: valkeyContainer,
	}

	t.Cleanup(func() {
		pool.Close()
		migrPool.Close()
		valkeyClient.Close()
		pgContainer.Terminate(ctx)
		valkeyContainer.Terminate(ctx)
	})

	return env
}
