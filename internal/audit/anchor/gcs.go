// GCS stores audit chain heads in a bucket protected by Bucket Lock
// retention. Object retention policy configuration remains operator-owned.
package anchor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"cloud.google.com/go/storage"
)

const GCSBackend = "gcs"

type GCS struct {
	client *storage.Client
	bucket string
}

var _ Anchor = (*GCS)(nil)

func NewGCS(client *storage.Client, bucket string) *GCS {
	return &GCS{client: client, bucket: bucket}
}

func NewGCSFromDefaultConfig(ctx context.Context, bucket string) (*GCS, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcs anchor: create client: %w", err)
	}
	return NewGCS(client, bucket), nil
}

func (g *GCS) Close() error {
	if g.client == nil {
		return nil
	}
	return g.client.Close()
}

func (g *GCS) Submit(ctx context.Context, head ChainHead) (ProofRef, error) {
	if g.client == nil {
		return ProofRef{}, errors.New("gcs anchor: client is required")
	}
	if g.bucket == "" {
		return ProofRef{}, errors.New("gcs anchor: bucket is required")
	}
	body, err := json.Marshal(head)
	if err != nil {
		return ProofRef{}, fmt.Errorf("gcs anchor: marshal: %w", err)
	}
	key := objectKey(head)
	w := g.client.Bucket(g.bucket).Object(key).NewWriter(ctx)
	w.ContentType = "application/json"
	if _, err := w.Write(body); err != nil {
		_ = w.Close()
		return ProofRef{}, fmt.Errorf("gcs anchor: write object: %w", err)
	}
	if err := w.Close(); err != nil {
		return ProofRef{}, fmt.Errorf("gcs anchor: close object: %w", err)
	}
	return ProofRef{Backend: GCSBackend, Ref: "gs://" + g.bucket + "/" + key}, nil
}

func (g *GCS) Verify(ctx context.Context, head ChainHead, proof ProofRef) error {
	if g.client == nil {
		return errors.New("gcs anchor: client is required")
	}
	if g.bucket == "" {
		return errors.New("gcs anchor: bucket is required")
	}
	key := keyFromRef(proof.Ref, "gs://"+g.bucket+"/")
	if key == "" {
		key = objectKey(head)
	}
	r, err := g.client.Bucket(g.bucket).Object(key).NewReader(ctx)
	if err != nil {
		return fmt.Errorf("gcs anchor: read object: %w", err)
	}
	defer func() { _ = r.Close() }()
	body, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("gcs anchor: read body: %w", err)
	}
	return verifyJSONHead(body, head)
}

func keyFromRef(ref, prefix string) string {
	if strings.HasPrefix(ref, prefix) {
		return strings.TrimPrefix(ref, prefix)
	}
	return ""
}
