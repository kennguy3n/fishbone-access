package gateway

import (
	"context"
	"fmt"
	"os"
)

// This file centralises how every binary opens the session-replay backend from
// the environment, so the gateway WRITE path and the control-plane READ paths
// always agree on the storage location AND on whether blobs are encrypted at
// rest. It is additive: the existing store constructors are untouched; this only
// composes them behind one entry point.

// ReplayBackend is a replay store that can write, read, and delete recordings —
// the full contract the recorder (write), the replay API (read), and the
// retention sweep (delete) collectively need. The filesystem, S3, in-memory,
// and encrypting stores all satisfy it.
type ReplayBackend interface {
	ReplayStore
	ReplayReader
	ReplayDeleter
}

// Compile-time proof that the encrypting decorator satisfies the FULL backend
// contract in one place, so a future narrowing of WrapWithEncryption's return
// type cannot silently drop the write/read/delete guarantee. The concrete
// filesystem/S3/memory stores are asserted at their own definitions.
var _ ReplayBackend = (*EncryptingReplayStore)(nil)

// OpenReplayStoreFromEnv selects the replay backend from the environment: an
// S3 bucket when PAM_REPLAY_S3_BUCKET is set, otherwise a filesystem store
// under PAM_REPLAY_DIR (default ./pam-replays). This is the single source of
// truth both the gateway and the control-plane use, so a recording the gateway
// writes is found by the API at the identical key.
func OpenReplayStoreFromEnv(ctx context.Context) (ReplayBackend, error) {
	if bucket := os.Getenv("PAM_REPLAY_S3_BUCKET"); bucket != "" {
		region := os.Getenv("PAM_REPLAY_S3_REGION")
		var opts []S3Option
		if ep := os.Getenv("PAM_REPLAY_S3_ENDPOINT"); ep != "" {
			opts = append(opts, WithEndpointURL(ep), WithForcePathStyle(true))
		}
		store, err := NewS3ReplayStore(ctx, bucket, region, opts...)
		if err != nil {
			return nil, fmt.Errorf("gateway: s3 replay store: %w", err)
		}
		return store, nil
	}
	dir := os.Getenv("PAM_REPLAY_DIR")
	if dir == "" {
		dir = "./pam-replays"
	}
	store, err := NewFilesystemReplayStore(dir)
	if err != nil {
		return nil, fmt.Errorf("gateway: filesystem replay store: %w", err)
	}
	return store, nil
}

// WrapWithEncryption returns base wrapped in per-workspace at-rest encryption
// when BOTH a sealer and a resolver are supplied; otherwise it returns base
// unchanged. This lets a caller "encrypt when a KMS key is configured, plain
// otherwise" with one call, and keeps the decision (and its backward-compatible
// plaintext passthrough) in one place across every binary. The wrapped store
// still satisfies ReplayBackend, so write/read/delete all flow through it.
func WrapWithEncryption(base ReplayBackend, sealer blobSealer, resolver SessionWorkspaceResolver) (ReplayBackend, error) {
	if sealer == nil || resolver == nil {
		return base, nil
	}
	enc, err := NewEncryptingReplayStore(base, sealer, resolver)
	if err != nil {
		return nil, err
	}
	return enc, nil
}
