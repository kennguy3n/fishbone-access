package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// This file adds the DELETE side of the replay stores, used by the retention
// sweep to tier a recording's heavy blob out of storage once it is older than
// the workspace's retention window. It is additive (new methods on the existing
// store types, declared in a new file) so recorder.go and the store files are
// untouched. Deleting the blob is the ONLY destructive part of retention: the
// session_recordings metadata row and the audit-chain event are always
// preserved, so the evidence a session happened (and its integrity digest)
// survives blob expiry.

// ReplayDeleter is a replay store that can remove a recording's blob. The
// retention sweep depends on this narrow interface so it can prune against any
// backend (filesystem, S3, the encrypting decorator) without knowing which. A
// delete of an already-absent recording is a no-op (idempotent), so a sweep
// that retries a partially-completed prune does not error.
type ReplayDeleter interface {
	DeleteReplay(ctx context.Context, sessionID string) error
}

// DeleteReplay removes the on-disk recording for sessionID. A missing file is
// not an error (idempotent prune).
func (s *FilesystemReplayStore) DeleteReplay(ctx context.Context, sessionID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := s.resolve(sessionID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("gateway: FilesystemReplayStore.DeleteReplay %s: %w", sessionID, err)
	}
	return nil
}

// DeleteReplay drops the in-memory recording for sessionID (idempotent).
func (s *MemoryReplayStore) DeleteReplay(_ context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, ReplayKey(sessionID))
	return nil
}

// s3Deleter is the slice of the S3 client needed to prune an object. The store's
// client is narrowed to s3API (Put/Get) so this file type-asserts to the delete
// capability rather than widening that interface in the existing file; the real
// *s3.Client satisfies it.
type s3Deleter interface {
	DeleteObject(ctx context.Context, in *s3.DeleteObjectInput, opts ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

// DeleteReplay removes the recording object for sessionID from the bucket. S3
// DeleteObject is idempotent (deleting an absent key succeeds), so a retried
// prune does not error.
func (s *S3ReplayStore) DeleteReplay(ctx context.Context, sessionID string) error {
	if s == nil || s.client == nil {
		return errors.New("gateway: S3ReplayStore is nil")
	}
	if sessionID == "" {
		return errors.New("gateway: S3ReplayStore.DeleteReplay: empty sessionID")
	}
	deleter, ok := s.client.(s3Deleter)
	if !ok {
		return errors.New("gateway: S3ReplayStore.DeleteReplay: client does not support DeleteObject")
	}
	key := ReplayKey(sessionID)
	if _, err := deleter.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: &key}); err != nil {
		return fmt.Errorf("gateway: S3ReplayStore.DeleteReplay: %w", err)
	}
	return nil
}

// DeleteReplay removes the blob through the wrapped store; the encrypting
// decorator holds no bytes of its own, so it simply delegates. inner is a
// ReplayBackend (which embeds ReplayDeleter), so the deleter is guaranteed at
// compile time — no runtime type assertion needed.
func (s *EncryptingReplayStore) DeleteReplay(ctx context.Context, sessionID string) error {
	return s.inner.DeleteReplay(ctx, sessionID)
}

// Compile-time assertions that the production stores can be pruned.
// (*EncryptingReplayStore is covered by the single ReplayBackend assertion in
// replay_encrypt.go, which embeds ReplayDeleter.)
var (
	_ ReplayDeleter = (*FilesystemReplayStore)(nil)
	_ ReplayDeleter = (*MemoryReplayStore)(nil)
	_ ReplayDeleter = (*S3ReplayStore)(nil)
)
