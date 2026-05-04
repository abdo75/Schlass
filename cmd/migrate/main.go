package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/abdo75/Schlass/internal/database"
)

func main() {
	direction := flag.String("direction", "up", "migration direction: up or down")
	steps := flag.Int("steps", 0, "number of steps for down/up; 0 means all available")
	flag.Parse()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("MIGRATIONS_DATABASE_URL")
	}
	if dbURL == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL or MIGRATIONS_DATABASE_URL must be set")
		os.Exit(2)
	}

	var err error
	switch *direction {
	case "up":
		if *steps > 0 {
			err = database.RunMigrationSteps(dbURL, *steps)
		} else {
			err = database.RunMigrations(dbURL)
		}
	case "down":
		if *steps > 0 {
			err = database.RunMigrationSteps(dbURL, -*steps)
		} else {
			err = database.RunMigrationsDown(dbURL)
		}
	default:
		fmt.Fprintf(os.Stderr, "invalid -direction %q (want up or down)\n", *direction)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		os.Exit(1)
	}
}
