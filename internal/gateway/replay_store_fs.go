package gateway

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// FilesystemReplayStore persists session recordings under a base directory,
// laid out by the canonical ReplayKey ("sessions/{id}/replay.bin"). It is the
// default store for single-node and development deployments; multi-node
// deployments wire S3ReplayStore instead.
//
// Writes are atomic: the payload lands in a temp file in the destination
// directory and is renamed into place, so a reader never observes a
// half-written recording and a crash mid-flush leaves no partial replay.bin.
type FilesystemReplayStore struct {
	base string
}

// NewFilesystemReplayStore roots a store at baseDir, creating it if needed.
func NewFilesystemReplayStore(baseDir string) (*FilesystemReplayStore, error) {
	if strings.TrimSpace(baseDir) == "" {
		return nil, fmt.Errorf("gateway: FilesystemReplayStore: base dir is required")
	}
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return nil, fmt.Errorf("gateway: FilesystemReplayStore: create base dir: %w", err)
	}
	return &FilesystemReplayStore{base: baseDir}, nil
}

// PutReplay writes the recording to {base}/sessions/{sessionID}/replay.bin.
func (s *FilesystemReplayStore) PutReplay(ctx context.Context, sessionID string, r io.Reader) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dest, err := s.resolve(sessionID)
	if err != nil {
		return err
	}
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("gateway: FilesystemReplayStore: create session dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, "replay-*.tmp")
	if err != nil {
		return fmt.Errorf("gateway: FilesystemReplayStore: create temp: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we error out before the rename; after a successful
	// rename the temp path no longer exists so Remove is a harmless no-op.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := io.Copy(tmp, r); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("gateway: FilesystemReplayStore: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("gateway: FilesystemReplayStore: close temp: %w", err)
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return fmt.Errorf("gateway: FilesystemReplayStore: rename into place: %w", err)
	}
	return nil
}

// resolve maps a session id to its on-disk path and defends against path
// traversal: a crafted session id ("../../etc") must never let a write escape
// the base directory.
func (s *FilesystemReplayStore) resolve(sessionID string) (string, error) {
	key := ReplayKey(sessionID)
	dest := filepath.Join(s.base, filepath.FromSlash(key))
	cleanBase := filepath.Clean(s.base)
	if dest != cleanBase && !strings.HasPrefix(dest, cleanBase+string(os.PathSeparator)) {
		return "", fmt.Errorf("gateway: FilesystemReplayStore: session id %q escapes base dir", sessionID)
	}
	return dest, nil
}

// MemoryReplayStore keeps recordings in memory. It exists for unit tests that
// assert on recorded bytes without touching disk or S3; it is safe for
// concurrent use.
type MemoryReplayStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

// NewMemoryReplayStore builds an empty in-memory store.
func NewMemoryReplayStore() *MemoryReplayStore {
	return &MemoryReplayStore{data: make(map[string][]byte)}
}

// PutReplay buffers the full payload keyed by ReplayKey(sessionID).
func (s *MemoryReplayStore) PutReplay(ctx context.Context, sessionID string, r io.Reader) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("gateway: MemoryReplayStore: read payload: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[ReplayKey(sessionID)] = b
	return nil
}

// Get returns the stored payload for sessionID and whether it was present.
func (s *MemoryReplayStore) Get(sessionID string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.data[ReplayKey(sessionID)]
	return b, ok
}
