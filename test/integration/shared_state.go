//go:build integration

package integration

import "github.com/testcontainers/testcontainers-go"

// Package-level shared-container state populated by TestMain and consumed by
// NewTestEnv. Kept in a non-test file so `go build -tags=integration` can
// compile the package during compile-only verification.
var (
	sharedPGContainer     testcontainers.Container
	sharedValkeyContainer testcontainers.Container
	sharedMigrConnString  string
	sharedAppConnString   string
	sharedPurgeConnString string
	sharedValkeyAddr      string
)
