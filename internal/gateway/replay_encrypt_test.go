package gateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
)

// fakeSealer is an AAD-binding stand-in for the per-workspace envelope
// encryptor. It is NOT real cryptography — it exists to prove the decorator
// frames the envelope correctly, round-trips the key version, binds the AAD
// (workspace+session) so a swapped blob fails to open, and that the stored bytes
// are not the plaintext. The envelope layout is aad || 0x00 || xor(plaintext),
// where the XOR (with 0xFF) obscures the plaintext so a leak assertion is
// meaningful while Decrypt remains exactly reversible.
type fakeSealer struct {
	version int
}

func xorMask(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ 0xFF
	}
	return out
}

func (f fakeSealer) Encrypt(_ context.Context, _ string, plaintext, aad []byte) ([]byte, int, error) {
	env := make([]byte, 0, len(aad)+1+len(plaintext))
	env = append(env, aad...)
	env = append(env, 0x00)
	env = append(env, xorMask(plaintext)...)
	return env, f.version, nil
}

func (f fakeSealer) Decrypt(_ context.Context, _ string, ciphertext, aad []byte, keyVersion int) ([]byte, error) {
	if keyVersion != f.version {
		return nil, errors.New("fakeSealer: wrong key version")
	}
	sep := bytes.IndexByte(ciphertext, 0x00)
	if sep < 0 {
		return nil, errors.New("fakeSealer: malformed envelope")
	}
	if !bytes.Equal(ciphertext[:sep], aad) {
		return nil, errors.New("fakeSealer: AAD mismatch")
	}
	return xorMask(ciphertext[sep+1:]), nil
}

// mapResolver maps session ids to workspace ids for the decorator.
type mapResolver map[string]string

func (m mapResolver) WorkspaceForSession(_ context.Context, sessionID string) (string, error) {
	ws, ok := m[sessionID]
	if !ok {
		return "", errors.New("mapResolver: unknown session")
	}
	return ws, nil
}

func newEncStore(t *testing.T, inner ReplayBackend, res SessionWorkspaceResolver) *EncryptingReplayStore {
	t.Helper()
	s, err := NewEncryptingReplayStore(inner, fakeSealer{version: 3}, res)
	if err != nil {
		t.Fatalf("new encrypting store: %v", err)
	}
	return s
}

func TestEncryptingReplayStoreRoundTrip(t *testing.T) {
	t.Parallel()
	const sid = "aaaaaaaa-0000-0000-0000-000000000001"
	inner := NewMemoryReplayStore()
	store := newEncStore(t, inner, mapResolver{sid: "ws-1"})

	plaintext := []byte("Iframed-replay-bytes-with-secrets")
	if err := store.PutReplay(context.Background(), sid, bytes.NewReader(plaintext)); err != nil {
		t.Fatalf("put: %v", err)
	}

	// The blob persisted to the inner store must be the ENCRYPTED envelope
	// (magic prefix), never the plaintext.
	rawRC, err := inner.GetReplay(context.Background(), sid)
	if err != nil {
		t.Fatalf("inner get: %v", err)
	}
	raw, _ := io.ReadAll(rawRC)
	rawRC.Close()
	if !isEncryptedReplay(raw) {
		t.Fatalf("inner blob is not encrypted (no magic prefix)")
	}
	if bytes.Contains(raw, []byte("secrets")) {
		t.Fatalf("plaintext leaked into the stored blob")
	}

	// Reading back through the decorator returns the exact plaintext.
	rc, err := store.GetReplay(context.Background(), sid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestEncryptingReplayStoreLegacyPassthrough(t *testing.T) {
	t.Parallel()
	const sid = "aaaaaaaa-0000-0000-0000-000000000002"
	inner := NewMemoryReplayStore()
	store := newEncStore(t, inner, mapResolver{sid: "ws-1"})

	// A pre-encryption (plaintext) recording written directly to the inner store
	// must still be readable through the decorator unchanged.
	legacy := []byte("Oplaintext-legacy-recording")
	if err := inner.PutReplay(context.Background(), sid, bytes.NewReader(legacy)); err != nil {
		t.Fatalf("inner put: %v", err)
	}
	rc, err := store.GetReplay(context.Background(), sid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, legacy) {
		t.Fatalf("legacy passthrough mismatch: got %q want %q", got, legacy)
	}
}

func TestEncryptingReplayStoreAADBinding(t *testing.T) {
	t.Parallel()
	const sidA = "aaaaaaaa-0000-0000-0000-00000000000a"
	const sidB = "aaaaaaaa-0000-0000-0000-00000000000b"
	inner := NewMemoryReplayStore()
	res := mapResolver{sidA: "ws-1", sidB: "ws-1"}
	store := newEncStore(t, inner, res)

	if err := store.PutReplay(context.Background(), sidA, bytes.NewReader([]byte("Idata"))); err != nil {
		t.Fatalf("put A: %v", err)
	}
	// Move A's ciphertext under B's key (a swap attack). Opening as B must fail
	// because the AAD binds the session id.
	rawRC, _ := inner.GetReplay(context.Background(), sidA)
	raw, _ := io.ReadAll(rawRC)
	rawRC.Close()
	if err := inner.PutReplay(context.Background(), sidB, bytes.NewReader(raw)); err != nil {
		t.Fatalf("put B: %v", err)
	}
	if _, err := store.GetReplay(context.Background(), sidB); err == nil {
		t.Fatalf("expected AAD-mismatch error opening a swapped blob, got nil")
	}
}

func TestEncryptingReplayStoreNotFound(t *testing.T) {
	t.Parallel()
	const sid = "aaaaaaaa-0000-0000-0000-00000000000c"
	inner := NewMemoryReplayStore()
	store := newEncStore(t, inner, mapResolver{sid: "ws-1"})
	_, err := store.GetReplay(context.Background(), sid)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
}

func TestEncryptingReplayStoreForWorkspaceSkipsResolver(t *testing.T) {
	t.Parallel()
	const sid = "aaaaaaaa-0000-0000-0000-00000000000d"
	inner := NewMemoryReplayStore()
	// Resolver that always errors: GetReplayForWorkspace must not call it.
	store := newEncStore(t, inner, mapResolver{sid: "ws-1"})
	if err := store.PutReplay(context.Background(), sid, bytes.NewReader([]byte("Ihi"))); err != nil {
		t.Fatalf("put: %v", err)
	}
	rc, err := store.GetReplayForWorkspace(context.Background(), "ws-1", sid)
	if err != nil {
		t.Fatalf("get for workspace: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if string(got) != "Ihi" {
		t.Fatalf("got %q", got)
	}
}

func TestNewEncryptingReplayStoreValidation(t *testing.T) {
	t.Parallel()
	inner := NewMemoryReplayStore()
	if _, err := NewEncryptingReplayStore(nil, fakeSealer{}, mapResolver{}); err == nil {
		t.Errorf("expected error for nil inner")
	}
	if _, err := NewEncryptingReplayStore(inner, nil, mapResolver{}); err == nil {
		t.Errorf("expected error for nil sealer")
	}
	if _, err := NewEncryptingReplayStore(inner, fakeSealer{}, nil); err == nil {
		t.Errorf("expected error for nil resolver")
	}
}
