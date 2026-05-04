// Package anchor defines write-once destinations for audit hash-chain heads.
// Backends persist only the current tenant chain head and return a proof ref
// that the audit scheduler stores in Postgres.
package anchor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Anchor interface {
	Submit(ctx context.Context, head ChainHead) (ProofRef, error)
	Verify(ctx context.Context, head ChainHead, proof ProofRef) error
}

type ChainHead struct {
	TenantID   uuid.UUID
	SequenceNo int64
	RowHash    []byte
	AnchoredAt time.Time
}

type ProofRef struct {
	Backend string
	Ref     string
}

const NoneBackend = "none"

type Noop struct{}

var _ Anchor = Noop{}

func (Noop) Submit(context.Context, ChainHead) (ProofRef, error) {
	return ProofRef{Backend: NoneBackend}, nil
}

func (Noop) Verify(context.Context, ChainHead, ProofRef) error {
	return nil
}

func objectKey(head ChainHead) string {
	return fmt.Sprintf("anchors/%s/%d.json", head.TenantID, head.SequenceNo)
}

func verifyJSONHead(body []byte, want ChainHead) error {
	var got ChainHead
	if err := json.Unmarshal(body, &got); err != nil {
		return fmt.Errorf("anchor: unmarshal head: %w", err)
	}
	if got.TenantID != want.TenantID || got.SequenceNo != want.SequenceNo {
		return errors.New("anchor: tenant or sequence mismatch")
	}
	if !bytes.Equal(got.RowHash, want.RowHash) {
		return errors.New("anchor: row_hash mismatch")
	}
	return nil
}
