package connutil

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestReadBodyLimit_UnderCap(t *testing.T) {
	want := []byte("small body")
	got, err := ReadBodyLimit(bytes.NewReader(want), 1024)
	if err != nil {
		t.Fatalf("ReadBodyLimit: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q; want %q", got, want)
	}
}

func TestReadBodyLimit_AtCap(t *testing.T) {
	want := bytes.Repeat([]byte("a"), 1024)
	got, err := ReadBodyLimit(bytes.NewReader(want), 1024)
	if err != nil {
		t.Fatalf("body exactly at the cap must be accepted: %v", err)
	}
	if len(got) != 1024 {
		t.Fatalf("got %d bytes; want 1024", len(got))
	}
}

// Regression: a body over the cap must FAIL CLOSED with an error, never return
// a silently truncated payload (which would reintroduce the audit data-loss
// bug this guard exists to prevent).
func TestReadBodyLimit_OverCapFailsClosed(t *testing.T) {
	body := bytes.Repeat([]byte("a"), 4096)
	got, err := ReadBodyLimit(bytes.NewReader(body), 1024)
	if err == nil {
		t.Fatal("expected error for over-cap body, got nil")
	}
	if got != nil {
		t.Fatalf("over-cap read must return nil bytes, got %d", len(got))
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v; want a cap-exceeded error", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestReadBodyLimit_PropagatesReadError(t *testing.T) {
	if _, err := ReadBodyLimit(errReader{}, 1024); err == nil {
		t.Fatal("expected read error to propagate, got nil")
	}
}

func TestReadBody_UsesDefaultCap(t *testing.T) {
	body := bytes.Repeat([]byte("x"), MaxResponseBytes+1)
	if _, err := ReadBody(bytes.NewReader(body)); err == nil {
		t.Fatal("expected default-cap overflow to fail closed, got nil")
	}
}
