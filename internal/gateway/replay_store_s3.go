package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// s3API is the slice of the S3 client the replay store uses. Narrowing to an
// interface lets unit tests substitute a fake without a live S3 endpoint and
// keeps the dependency on the SDK surface explicit.
type s3API interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// S3ReplayStore persists session recordings to an S3-compatible bucket under
// the canonical ReplayKey. It is the multi-node production store; single-node
// deployments use FilesystemReplayStore.
//
// Data residency is fail-closed: when the store is constructed with a required
// residency region, EnforceResidency rejects any workspace whose configured
// residency does not match before a single byte is uploaded, so a recording for
// an EU-resident tenant can never be flushed to a US bucket.
type S3ReplayStore struct {
	client    s3API
	bucket    string
	region    string
	residency string
}

// S3Option configures an S3ReplayStore at construction.
type S3Option func(*s3ReplayStoreOptions)

type s3ReplayStoreOptions struct {
	endpointURL    string
	forcePathStyle bool
	residency      string
}

// WithEndpointURL overrides the S3 endpoint (MinIO/LocalStack in dev).
func WithEndpointURL(url string) S3Option {
	return func(o *s3ReplayStoreOptions) { o.endpointURL = url }
}

// WithForcePathStyle enables path-style addressing, required by MinIO and some
// S3-compatible stores.
func WithForcePathStyle(v bool) S3Option {
	return func(o *s3ReplayStoreOptions) { o.forcePathStyle = v }
}

// WithResidency declares the data-residency region this bucket satisfies.
// When set, EnforceResidency fails closed for any workspace pinned to a
// different region.
func WithResidency(region string) S3Option {
	return func(o *s3ReplayStoreOptions) { o.residency = strings.TrimSpace(region) }
}

// NewS3ReplayStore builds a store uploading to s3://{bucket}/sessions/{id}/replay.bin.
// Credentials load from the standard AWS chain (env, IAM role, config file).
func NewS3ReplayStore(ctx context.Context, bucket, region string, opts ...S3Option) (*S3ReplayStore, error) {
	if strings.TrimSpace(bucket) == "" {
		return nil, errors.New("gateway: S3ReplayStore: bucket is required")
	}
	if strings.TrimSpace(region) == "" {
		region = "us-east-1"
	}
	var so s3ReplayStoreOptions
	for _, o := range opts {
		o(&so)
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("gateway: S3ReplayStore: load AWS config: %w", err)
	}
	var s3Opts []func(*s3.Options)
	if so.endpointURL != "" {
		ep := so.endpointURL
		s3Opts = append(s3Opts, func(o *s3.Options) { o.BaseEndpoint = &ep })
	}
	if so.forcePathStyle {
		s3Opts = append(s3Opts, func(o *s3.Options) { o.UsePathStyle = true })
	}
	return &S3ReplayStore{
		client:    s3.NewFromConfig(cfg, s3Opts...),
		bucket:    bucket,
		region:    region,
		residency: so.residency,
	}, nil
}

// EnforceResidency returns an error when this store may not lawfully hold a
// recording for a workspace pinned to workspaceResidency. An empty workspace
// residency means "no constraint" and always passes. A store with no declared
// residency cannot make the guarantee, so it fails closed for any constrained
// workspace.
func (s *S3ReplayStore) EnforceResidency(workspaceResidency string) error {
	want := strings.TrimSpace(workspaceResidency)
	if want == "" {
		return nil
	}
	if s.residency == "" {
		return fmt.Errorf("gateway: S3ReplayStore: workspace requires residency %q but bucket declares none", want)
	}
	if !strings.EqualFold(s.residency, want) {
		return fmt.Errorf("gateway: S3ReplayStore: workspace residency %q does not match bucket residency %q", want, s.residency)
	}
	return nil
}

// PutReplay uploads the recording for sessionID under the canonical key.
func (s *S3ReplayStore) PutReplay(ctx context.Context, sessionID string, r io.Reader) error {
	if s == nil || s.client == nil {
		return errors.New("gateway: S3ReplayStore is nil")
	}
	if sessionID == "" {
		return errors.New("gateway: S3ReplayStore.PutReplay: empty sessionID")
	}
	key := ReplayKey(sessionID)
	if _, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &s.bucket,
		Key:    &key,
		Body:   r,
	}); err != nil {
		return fmt.Errorf("gateway: S3ReplayStore.PutReplay: %w", err)
	}
	return nil
}

// GetReplay downloads the recording for sessionID.
func (s *S3ReplayStore) GetReplay(ctx context.Context, sessionID string) (io.ReadCloser, error) {
	if s == nil || s.client == nil {
		return nil, errors.New("gateway: S3ReplayStore is nil")
	}
	if sessionID == "" {
		return nil, errors.New("gateway: S3ReplayStore.GetReplay: empty sessionID")
	}
	key := ReplayKey(sessionID)
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &key})
	if err != nil {
		return nil, fmt.Errorf("gateway: S3ReplayStore.GetReplay: %w", err)
	}
	return out.Body, nil
}
