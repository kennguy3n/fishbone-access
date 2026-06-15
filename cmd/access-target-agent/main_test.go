package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPersistIdentityRoundTrips writes an identity and loads it back unchanged.
func TestPersistIdentityRoundTrips(t *testing.T) {
	dir := t.TempDir()
	want := &identity{
		agentID:   "agent-1",
		relayAddr: "relay.example:7443",
		keyPEM:    []byte("KEY"),
		certPEM:   []byte("CERT"),
		caPEM:     []byte("CA"),
	}
	if err := persistIdentity(dir, want, time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("persist: %v", err)
	}

	got, ok, err := loadIdentity(dir)
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	if got.agentID != want.agentID || got.relayAddr != want.relayAddr ||
		string(got.keyPEM) != "KEY" || string(got.certPEM) != "CERT" || string(got.caPEM) != "CA" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	// No temp files must linger after a successful persist.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("leftover temp file after persist: %s", e.Name())
		}
	}
}

// TestPersistIdentityWritesKeyLast proves the crash-safety ordering: the key
// file (the one loadIdentity gates on) is created only after cert, CA, and meta
// exist, so a crash mid-persist can never leave a key without its companions —
// the state a stuck, unrecoverable agent would require.
func TestPersistIdentityWritesKeyLast(t *testing.T) {
	dir := t.TempDir()
	id := &identity{agentID: "a", relayAddr: "r:1", keyPEM: []byte("K"), certPEM: []byte("C"), caPEM: []byte("A")}
	if err := persistIdentity(dir, id, time.Unix(1, 0)); err != nil {
		t.Fatalf("persist: %v", err)
	}
	keyInfo, err := os.Stat(filepath.Join(dir, keyFile))
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	for _, companion := range []string{certFile, caFile, metaFile} {
		ci, err := os.Stat(filepath.Join(dir, companion))
		if err != nil {
			t.Fatalf("stat %s: %v", companion, err)
		}
		if keyInfo.ModTime().Before(ci.ModTime()) {
			t.Fatalf("key file written before %s; crash safety relies on key being last", companion)
		}
	}
}

// TestAtomicWriteFileReplaces proves a second write fully replaces the first
// (no partial/torn content) and applies the requested mode.
func TestAtomicWriteFileReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := atomicWriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if err := atomicWriteFile(path, []byte("second-longer"), 0o600); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- test path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "second-longer" {
		t.Fatalf("content = %q, want %q", got, "second-longer")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("perm = %o, want 600", perm)
	}
}
