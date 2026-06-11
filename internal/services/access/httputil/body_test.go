package httputil

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadAllLimited_ReadsFullBodyUnderLimit(t *testing.T) {
	// A body well under the limit is returned in full — no truncation, the
	// regression that the old 1 MiB caps caused.
	want := strings.Repeat("a", 5_000_000) // 5 MB, far above the old 1 MiB cap
	got, err := ReadAllLimited(strings.NewReader(want), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != want {
		t.Fatalf("body truncated: got %d bytes, want %d", len(got), len(want))
	}
}

func TestReadAllLimited_AcceptsExactlyLimit(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 1024)
	got, err := ReadAllLimited(bytes.NewReader(data), 1024)
	if err != nil {
		t.Fatalf("body of exactly the limit must be accepted, got error: %v", err)
	}
	if len(got) != 1024 {
		t.Fatalf("got %d bytes, want 1024", len(got))
	}
}

func TestReadAllLimited_ErrorsInsteadOfTruncating(t *testing.T) {
	// The key invariant distinguishing this from the old caps: exceeding the
	// limit is a loud error, never a silent truncation.
	data := bytes.Repeat([]byte("y"), 2048)
	got, err := ReadAllLimited(bytes.NewReader(data), 1024)
	if err == nil {
		t.Fatalf("expected error for over-limit body, got %d bytes and nil error", len(got))
	}
	if got != nil {
		t.Fatalf("expected nil body on over-limit, got %d bytes", len(got))
	}
}

func TestReadAllLimited_NilReader(t *testing.T) {
	if _, err := ReadAllLimited(nil, 0); err == nil {
		t.Fatal("expected error for nil reader")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestReadAllLimited_PropagatesReadError(t *testing.T) {
	if _, err := ReadAllLimited(io.Reader(errReader{}), 0); err == nil {
		t.Fatal("expected underlying read error to propagate")
	}
}
