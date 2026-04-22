package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/abdo75/Schlass/internal/database"
	"github.com/abdo75/Schlass/internal/requestcontext"
)

type AuditEntry struct {
	EventType  string
	ActorID    *uuid.UUID
	ActorEmail string
	TargetType string
	TargetID   string
	ClientID   *uuid.UUID
	IPAddress  string
	Outcome    string
	Metadata   map[string]any
}

type AuditStore struct{}

func NewAuditStore() *AuditStore {
	return &AuditStore{}
}

func (s *AuditStore) Log(ctx context.Context, q database.Querier, entry AuditEntry) error {
	// Merge correlation_id from request context so audit rows can be joined
	// against the access log. Empty in contexts that bypass RequestLogging
	// (CLI tools, fabricated test contexts) — omit the key rather than
	// write a misleading empty string.
	metadata := entry.Metadata
	if cid := requestcontext.CorrelationID(ctx); cid != "" {
		merged := make(map[string]any, len(metadata)+1)
		for k, v := range metadata {
			merged[k] = v
		}
		merged["correlation_id"] = cid
		metadata = merged
	}

	var metadataJSON []byte
	if metadata != nil {
		var err error
		metadataJSON, err = json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf("audit log: failed to marshal metadata: %w", err)
		}
	}

	// ip_address is INET + nullable — pass nil when empty; pgx would
	// otherwise cast "" to inet and Postgres rejects with 22P02.
	var ipAddress *string
	if entry.IPAddress != "" {
		ipAddress = &entry.IPAddress
	}

	_, err := q.Exec(ctx,
		`INSERT INTO audit_logs (event_type, actor_id, actor_email, target_type, target_id, client_id, ip_address, outcome, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		entry.EventType,
		entry.ActorID,
		entry.ActorEmail,
		entry.TargetType,
		entry.TargetID,
		entry.ClientID,
		ipAddress,
		entry.Outcome,
		metadataJSON,
	)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	return nil
}

// PseudonymizeUser dispatches to the audit_log_pseudonymize_user
// SECURITY DEFINER function (migration 000018) — the single sanctioned
// mutation on audit_logs. schlass_app has no direct UPDATE on the table,
// only EXECUTE on this function. GDPR Art. 17(3)(b) compliance path.
func (s *AuditStore) PseudonymizeUser(ctx context.Context, q database.Querier, userID uuid.UUID) (int, error) {
	var rows int
	if err := q.QueryRow(ctx, `SELECT audit_log_pseudonymize_user($1)`, userID).Scan(&rows); err != nil {
		return 0, fmt.Errorf("audit pseudonymize: %w", err)
	}
	return rows, nil
}
