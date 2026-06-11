package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestFlushComputesRecordingDigest proves Flush hashes exactly the bytes it
// persists and exposes them via Recording(), so the audit chain can anchor a
// reference an auditor can re-verify against the stored replay.bin.
func TestFlushComputesRecordingDigest(t *testing.T) {
	ctx := context.Background()
	store := newMemReplayStore()
	rec := NewIORecorder(ctx, "sess-digest", 0)

	rec.Record(DirInput, []byte("whoami\n"))
	rec.Record(DirOutput, []byte("root\n"))

	if err := rec.Flush(ctx, store); err != nil {
		t.Fatalf("flush: %v", err)
	}

	got := rec.Recording()
	if !got.Stored {
		t.Fatalf("expected Stored=true after flush to a store")
	}
	if got.Key != ReplayKey("sess-digest") {
		t.Fatalf("key = %q, want %q", got.Key, ReplayKey("sess-digest"))
	}

	// The digest must cover exactly the bytes handed to the store.
	persisted, ok := store.data["sess-digest"]
	if !ok {
		t.Fatalf("recording was not persisted to the store")
	}
	sum := sha256.Sum256(persisted)
	wantHex := hex.EncodeToString(sum[:])
	if got.SHA256 != wantHex {
		t.Fatalf("sha256 = %q, want %q (over %d persisted bytes)", got.SHA256, wantHex, len(persisted))
	}
	if got.Bytes != int64(len(persisted)) {
		t.Fatalf("bytes = %d, want %d", got.Bytes, len(persisted))
	}
	if got.Truncated {
		t.Fatalf("unexpected truncated flag for an uncapped recording")
	}
}

// TestFlushNilStoreNotStored confirms a recording-disabled flush (nil store)
// still computes the digest but reports Stored=false, so the teardown path does
// not anchor a dangling recording reference to an artifact that was never
// persisted.
func TestFlushNilStoreNotStored(t *testing.T) {
	ctx := context.Background()
	rec := NewIORecorder(ctx, "sess-nostore", 0)
	rec.Record(DirOutput, []byte("hello"))

	if err := rec.Flush(ctx, nil); err != nil {
		t.Fatalf("flush nil store: %v", err)
	}
	got := rec.Recording()
	if got.Stored {
		t.Fatalf("expected Stored=false when flushing with a nil store")
	}
	if got.SHA256 == "" {
		t.Fatalf("digest should still be computed even without a store")
	}
}

// TestFlushTruncatedRecordingFlagged proves the size cap surfaces through the
// recording descriptor so the evidence reference records that the capture was
// incomplete.
func TestFlushTruncatedRecordingFlagged(t *testing.T) {
	ctx := context.Background()
	store := newMemReplayStore()
	rec := NewIORecorder(ctx, "sess-trunc", 8)

	rec.Record(DirOutput, []byte("0123456789abcdef")) // exceeds the 8-byte cap

	if err := rec.Flush(ctx, store); err != nil {
		t.Fatalf("flush: %v", err)
	}
	got := rec.Recording()
	if !got.Stored {
		t.Fatalf("expected Stored=true")
	}
	if !got.Truncated {
		t.Fatalf("expected Truncated=true once the size cap dropped payload")
	}
}
