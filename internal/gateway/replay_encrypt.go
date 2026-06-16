package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// This file adds OPTIONAL at-rest encryption for the replay blob. The recorder
// already anchors a SHA-256 in the audit chain for tamper-evidence (integrity),
// but a recording also contains CONFIDENTIAL payload — typed secrets, query
// results — so the blob itself should be encrypted at rest, not only hashed.
// EncryptingReplayStore is a transparent decorator over any ReplayStore that
// seals the blob under a per-workspace DEK (AES-256-GCM) on write and opens it
// on read, leaving the recorder, the frame format, and the store backends
// untouched. It is wired only when a key manager is configured; otherwise the
// plain store is used and behaviour is unchanged.

// blobSealer is the subset of the per-workspace envelope encryptor this store
// needs. It is declared here (rather than importing the access package) so the
// gateway has no dependency on the control-plane service layer — the production
// *access.EnvelopeEncryptor satisfies it structurally. Encrypt seals plaintext
// under the workspace's latest DEK and returns the envelope plus the key
// version to persist; Decrypt opens an envelope under the recorded version.
type blobSealer interface {
	Encrypt(ctx context.Context, workspaceID string, plaintext, aad []byte) (ciphertext []byte, keyVersion int, err error)
	Decrypt(ctx context.Context, workspaceID string, ciphertext, aad []byte, keyVersion int) (plaintext []byte, err error)
}

// SessionWorkspaceResolver maps a session id to its owning workspace id. The
// encrypting store needs the workspace to derive the per-workspace DEK, but the
// ReplayStore API is keyed only by session id, so the decorator resolves the
// workspace through this seam (a GORM-backed lookup in production). The returned
// workspace id must be the canonical UUID string used everywhere else.
type SessionWorkspaceResolver interface {
	WorkspaceForSession(ctx context.Context, sessionID string) (workspaceID string, err error)
}

// replayEnvelopeMagic prefixes an encrypted replay blob. Its first byte (0x53,
// 'S') can never begin a plaintext framed recording — the first byte of a
// recording is always a direction tag (DirInput 'I', DirOutput 'O', DirControl
// 'C') — so a reader can unambiguously tell an encrypted blob from a legacy
// plaintext one and stay backward-compatible with recordings written before
// encryption was enabled.
var replayEnvelopeMagic = []byte{'S', 'N', 'R', '1'}

// replayEnvelopeHeaderLen is the fixed prefix on an encrypted blob: the 4-byte
// magic plus a 4-byte big-endian key version. The sealed envelope follows.
const replayEnvelopeHeaderLen = 4 + 4

// EncryptingReplayStore wraps an inner ReplayStore and a per-workspace sealer to
// encrypt recordings at rest. On write it seals the exact bytes the recorder
// produced and stores magic+version+envelope; on read it detects the magic,
// opens the envelope, and yields the original plaintext — or passes a
// pre-encryption (legacy plaintext) blob through unchanged. The SHA-256 the
// gateway anchors is computed over the PLAINTEXT framed bytes before this
// decorator seals them, so re-hashing a decrypted recording still matches the
// audit-chain digest.
type EncryptingReplayStore struct {
	inner    ReplayBackend
	sealer   blobSealer
	resolver SessionWorkspaceResolver
}

// NewEncryptingReplayStore wraps inner so recordings are sealed under a
// per-workspace DEK. All three dependencies are required; a nil argument is a
// programming error (the caller must wire the plain store when encryption is
// not configured rather than pass nils here). inner is a full ReplayBackend
// (store + reader + deleter) so the decorator can persist, fetch, AND prune
// through it without a runtime type assertion — the deleter capability is
// guaranteed at compile time, matching the ReplayBackend assertion below.
func NewEncryptingReplayStore(inner ReplayBackend, sealer blobSealer, resolver SessionWorkspaceResolver) (*EncryptingReplayStore, error) {
	if inner == nil {
		return nil, errors.New("gateway: EncryptingReplayStore: inner store is required")
	}
	if sealer == nil {
		return nil, errors.New("gateway: EncryptingReplayStore: sealer is required")
	}
	if resolver == nil {
		return nil, errors.New("gateway: EncryptingReplayStore: workspace resolver is required")
	}
	return &EncryptingReplayStore{inner: inner, sealer: sealer, resolver: resolver}, nil
}

// replayAAD binds an envelope to its workspace AND session so a sealed blob
// cannot be swapped to another session or replayed under another tenant: GCM
// authenticates this as Additional Authenticated Data, so Open fails if either
// changes.
func replayAAD(workspaceID, sessionID string) []byte {
	return []byte("replay:" + workspaceID + ":" + sessionID)
}

// PutReplay seals the recording for sessionID under its workspace DEK and writes
// magic+version+envelope to the inner store.
func (s *EncryptingReplayStore) PutReplay(ctx context.Context, sessionID string, r io.Reader) error {
	if sessionID == "" {
		return errors.New("gateway: EncryptingReplayStore.PutReplay: empty sessionID")
	}
	workspaceID, err := s.resolver.WorkspaceForSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("gateway: EncryptingReplayStore.PutReplay: resolve workspace for %s: %w", sessionID, err)
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("gateway: EncryptingReplayStore.PutReplay: read plaintext: %w", err)
	}
	envelope, keyVersion, err := s.sealer.Encrypt(ctx, workspaceID, plaintext, replayAAD(workspaceID, sessionID))
	if err != nil {
		return fmt.Errorf("gateway: EncryptingReplayStore.PutReplay: seal %s: %w", sessionID, err)
	}
	framed := make([]byte, 0, replayEnvelopeHeaderLen+len(envelope))
	framed = append(framed, replayEnvelopeMagic...)
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], uint32(keyVersion))
	framed = append(framed, ver[:]...)
	framed = append(framed, envelope...)
	return s.inner.PutReplay(ctx, sessionID, bytes.NewReader(framed))
}

// GetReplay fetches and decrypts the recording for sessionID, resolving the
// workspace through the resolver. A legacy plaintext blob (no magic) is returned
// unchanged. A missing recording surfaces the inner store's os.ErrNotExist so
// the HTTP edge maps it to 404.
func (s *EncryptingReplayStore) GetReplay(ctx context.Context, sessionID string) (io.ReadCloser, error) {
	workspaceID, err := s.resolver.WorkspaceForSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("gateway: EncryptingReplayStore.GetReplay: resolve workspace for %s: %w", sessionID, err)
	}
	return s.GetReplayForWorkspace(ctx, workspaceID, sessionID)
}

// GetReplayForWorkspace is GetReplay for a caller that already knows the
// workspace (every authenticated replay handler resolves the session first), so
// it skips the resolver round-trip. The decryption result is identical.
func (s *EncryptingReplayStore) GetReplayForWorkspace(ctx context.Context, workspaceID, sessionID string) (io.ReadCloser, error) {
	if workspaceID == "" {
		return nil, errors.New("gateway: EncryptingReplayStore.GetReplay: empty workspaceID")
	}
	rc, err := s.inner.GetReplay(ctx, sessionID)
	if err != nil {
		return nil, err // includes os.ErrNotExist, preserved for the 404 mapping
	}
	defer rc.Close()
	stored, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("gateway: EncryptingReplayStore.GetReplay: read %s: %w", sessionID, err)
	}
	plaintext, err := s.open(ctx, workspaceID, sessionID, stored)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(plaintext)), nil
}

// open returns the plaintext for a stored blob: it decrypts an enveloped blob
// (magic present) and passes a legacy plaintext blob through unchanged.
func (s *EncryptingReplayStore) open(ctx context.Context, workspaceID, sessionID string, stored []byte) ([]byte, error) {
	if !isEncryptedReplay(stored) {
		// Pre-encryption recording: return as-is so old sessions still replay.
		return stored, nil
	}
	keyVersion := int(binary.BigEndian.Uint32(stored[4:8]))
	envelope := stored[replayEnvelopeHeaderLen:]
	plaintext, err := s.sealer.Decrypt(ctx, workspaceID, envelope, replayAAD(workspaceID, sessionID), keyVersion)
	if err != nil {
		return nil, fmt.Errorf("gateway: EncryptingReplayStore.GetReplay: open %s: %w", sessionID, err)
	}
	return plaintext, nil
}

// isEncryptedReplay reports whether stored begins with the envelope magic and is
// long enough to carry the fixed header.
func isEncryptedReplay(stored []byte) bool {
	return len(stored) >= replayEnvelopeHeaderLen && bytes.Equal(stored[:4], replayEnvelopeMagic)
}

// Ensure EncryptingReplayStore satisfies the full store contract (write + read +
// delete) in one assertion, so it can be wired as the write store (gateway), the
// read store (control plane), and the prune store (workflow engine) — and so the
// inner-field deleter delegation in DeleteReplay is guaranteed at compile time.
var _ ReplayBackend = (*EncryptingReplayStore)(nil)
