package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/abdo75/Schlass/internal/database"
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
	var metadataJSON []byte
	if entry.Metadata != nil {
		var err error
		metadataJSON, err = json.Marshal(entry.Metadata)
		if err != nil {
			return fmt.Errorf("audit log: failed to marshal metadata: %w", err)
		}
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
		entry.IPAddress,
		entry.Outcome,
		metadataJSON,
	)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	return nil
}
