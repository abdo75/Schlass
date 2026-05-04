// S3 stores audit chain heads in Object Lock COMPLIANCE mode. Bucket
// ownership, versioning, and Object Lock enablement stay with the operator.
package anchor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const S3Backend = "s3"

type S3 struct {
	client           *s3.Client
	bucket           string
	hotRetentionDays int
}

var _ Anchor = (*S3)(nil)

func NewS3(client *s3.Client, bucket string, hotRetentionDays int) *S3 {
	if hotRetentionDays <= 0 {
		hotRetentionDays = 365
	}
	return &S3{client: client, bucket: bucket, hotRetentionDays: hotRetentionDays}
}

func NewS3FromDefaultConfig(ctx context.Context, bucket string, hotRetentionDays int) (*S3, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("s3 anchor: load config: %w", err)
	}
	return NewS3(s3.NewFromConfig(cfg), bucket, hotRetentionDays), nil
}

func (s *S3) Submit(ctx context.Context, head ChainHead) (ProofRef, error) {
	if s.client == nil {
		return ProofRef{}, errors.New("s3 anchor: client is required")
	}
	if s.bucket == "" {
		return ProofRef{}, errors.New("s3 anchor: bucket is required")
	}
	body, err := json.Marshal(head)
	if err != nil {
		return ProofRef{}, fmt.Errorf("s3 anchor: marshal: %w", err)
	}
	key := objectKey(head)
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:                    aws.String(s.bucket),
		Key:                       aws.String(key),
		Body:                      bytes.NewReader(body),
		ContentType:               aws.String("application/json"),
		ObjectLockMode:            types.ObjectLockModeCompliance,
		ObjectLockRetainUntilDate: aws.Time(time.Now().UTC().AddDate(0, 0, s.hotRetentionDays)),
	})
	if err != nil {
		return ProofRef{}, fmt.Errorf("s3 anchor: put object: %w", err)
	}
	return ProofRef{Backend: S3Backend, Ref: "s3://" + s.bucket + "/" + key}, nil
}

func (s *S3) Verify(ctx context.Context, head ChainHead, proof ProofRef) error {
	if s.client == nil {
		return errors.New("s3 anchor: client is required")
	}
	if s.bucket == "" {
		return errors.New("s3 anchor: bucket is required")
	}
	key := keyFromRef(proof.Ref, "s3://"+s.bucket+"/")
	if key == "" {
		key = objectKey(head)
	}
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("s3 anchor: get object: %w", err)
	}
	defer func() { _ = out.Body.Close() }()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		return fmt.Errorf("s3 anchor: read object: %w", err)
	}
	return verifyJSONHead(body, head)
}
