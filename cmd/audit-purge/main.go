package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/abdo75/Schlass/internal/audit/retention"
	"github.com/abdo75/Schlass/internal/database"
	"github.com/abdo75/Schlass/internal/instanceconfig"
)

func main() {
	dryRun := flag.Bool("dry-run", false, "list actions without exporting or dropping partitions")
	operationalDays := flag.Int("operational-days", 0, "override operational retention days")
	securityHotDays := flag.Int("security-hot-days", 0, "override security hot retention days")
	outputDir := flag.String("output-dir", "", "directory for local Parquet cold exports")
	flag.Parse()
	dbURL := os.Getenv("SCHLASS_PURGE_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("DATABASE_URL")
		if dbURL == "" {
			fmt.Fprintln(os.Stderr, "SCHLASS_PURGE_DATABASE_URL is not set")
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "warning: SCHLASS_PURGE_DATABASE_URL is not set; falling back to DATABASE_URL")
	}
	ctx := context.Background()
	pool, err := database.NewPool(ctx, dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()
	cfgStore := instanceconfig.NewStore()
	cfg := instanceconfig.NewService(cfgStore, nil)
	results, err := retention.Purge(ctx, pool, retention.PurgeOptions{
		DryRun:          *dryRun,
		OutputDir:       *outputDir,
		OperationalDays: *operationalDays,
		SecurityHotDays: *securityHotDays,
		InstanceConfig:  cfg,
		ConfigStore:     cfgStore,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "purge: %v\n", err)
		printResults(results)
		os.Exit(1)
	}
	if len(results) == 0 {
		fmt.Println("no partitions qualified")
		return
	}
	printResults(results)
}

func printResults(results []retention.PurgeResult) {
	for _, res := range results {
		if res.Warning != "" {
			fmt.Printf("partition=%s action=%s warning=%q\n", res.PartitionName, res.Action, res.Warning)
			continue
		}
		fmt.Printf("partition=%s action=%s rows=%d proof_ref=%s\n",
			res.PartitionName, res.Action, res.RowsAffected, res.ProofRef)
	}
}
