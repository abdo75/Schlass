package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/abdo75/Schlass/internal/audit/retention"
	"github.com/abdo75/Schlass/internal/database"
)

func main() {
	partition := flag.String("partition", "", "audit partition table name, e.g. audit_logs_202504")
	output := flag.String("output", "", "Parquet output path")
	backend := flag.String("backend", "local", "cold-tier backend label")
	flag.Parse()
	if *partition == "" || *output == "" {
		flag.Usage()
		os.Exit(2)
	}
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL is not set")
		os.Exit(2)
	}
	ctx := context.Background()
	pool, err := database.NewPool(ctx, dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()
	res, err := retention.ExportCold(ctx, pool, retention.ExportOptions{
		Partition: *partition,
		Output:    *output,
		Backend:   *backend,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "export: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("exported partition=%s rows=%d output=%s sha256=%s proof_ref=%s\n",
		*partition, res.Rows, res.Path, retention.SHA256Hex(res.SHA256), res.ProofRef)
}
