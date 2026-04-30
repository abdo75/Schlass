// audit-verify walks the audit_logs hash chain for one tenant and
// reports the first divergence (mismatch or sequence gap), or exits
// cleanly if the chain re-walks intact.
//
// Exit codes:
//   0 — clean
//   1 — hash mismatch detected
//   2 — sequence gap detected
//   3 — operational error (DB connect, query, parse)
//
// Legacy rows: rows inserted before the M3 hash-chain migration carry
// a deterministic sentinel row_hash (sha256("legacy:" || id)) and
// prev_hash = NULL. The verifier accepts those as opaque-but-
// continuous and only enforces canonical-JSON re-derivation from the
// first M3-emitted row onward. See internal/audit/chain.go for the
// sentinel scheme.
//
// Usage:
//
//	audit-verify --since=<rfc3339> [--tenant=<uuid>]
//
// DB URL is read from DATABASE_URL.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/abdo75/Schlass/internal/audit"
)

func main() {
	since := flag.String("since", "", "RFC 3339 timestamp; rows before this are skipped (default: walk entire chain)")
	tenant := flag.String("tenant", "", "tenant UUID (default: SingleTenant constant)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `audit-verify - walks the audit_logs hash chain.

Walks one tenant's rows in sequence_no order, recomputes each
row_hash from the canonical JSON of the row plus its prev_hash, and
reports the first divergence.

Legacy rows (sentinel row_hash, prev_hash NULL) are accepted as
opaque-but-continuous; the chain is only re-derived from the first
M3-emitted row onward.

DATABASE_URL must be set in the environment.

Exit codes: 0 clean, 1 mismatch, 2 gap, 3 operational error.

Flags:
`)
		flag.PrintDefaults()
	}
	flag.Parse()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL is not set")
		os.Exit(3)
	}

	opts := audit.VerifyOptions{}
	if *since != "" {
		t, err := time.Parse(time.RFC3339, *since)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid --since (want RFC 3339): %v\n", err)
			os.Exit(3)
		}
		opts.Since = t
	}
	if *tenant != "" {
		t, err := uuid.Parse(*tenant)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid --tenant: %v\n", err)
			os.Exit(3)
		}
		opts.TenantID = t
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(3)
	}
	defer func() { _ = conn.Close(ctx) }()

	report, err := audit.Verify(ctx, conn, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify: %v\n", err)
		os.Exit(3)
	}

	if report.Mismatch != nil {
		m := report.Mismatch
		fmt.Printf("BREAK at sequence_no=%d event_id=%s expected=%s got=%s\n",
			m.SequenceNo, m.EventID, m.ExpectedHex, m.GotHex)
		os.Exit(1)
	}
	if report.Gap != nil {
		g := report.Gap
		fmt.Printf("GAP missing sequence_no=%d (last seen=%d)\n",
			g.MissingSequenceNo, g.LastSeenSequenceNo)
		os.Exit(2)
	}

	fmt.Printf("OK tenant=%s rows_checked=%d\n", report.TenantID, report.RowsChecked)
}
