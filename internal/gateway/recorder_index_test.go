package gateway

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// buildRecording records the given frames through a real IORecorder and flushes
// them to an in-memory store, returning the store, the integrity descriptor, and
// the session id — exercising the exact write path the gateway uses in
// production so the decoder is tested against real framed bytes.
func buildRecording(t *testing.T, sessionID string, maxBytes int, frames []struct {
	dir     Direction
	payload string
}) (*MemoryReplayStore, Recording) {
	t.Helper()
	rec := NewIORecorder(context.Background(), sessionID, maxBytes)
	for _, f := range frames {
		rec.Record(f.dir, []byte(f.payload))
	}
	store := NewMemoryReplayStore()
	if err := rec.Flush(context.Background(), store); err != nil {
		t.Fatalf("flush: %v", err)
	}
	return store, rec.Recording()
}

func readBlob(t *testing.T, store ReplayReader, sessionID string) io.ReadCloser {
	t.Helper()
	rc, err := store.GetReplay(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("get replay: %v", err)
	}
	return rc
}

func TestDecodeAndVerify(t *testing.T) {
	t.Parallel()
	const sid = "11111111-1111-1111-1111-111111111111"
	store, recDesc := buildRecording(t, sid, 1<<20, []struct {
		dir     Direction
		payload string
	}{
		{DirControl, "session opened"},
		{DirInput, "ls -la\r"},
		{DirOutput, "total 0\r\n"},
		{DirInput, "whoami\r"},
		{DirOutput, "root\r\n"},
	})

	t.Run("verified with correct digest", func(t *testing.T) {
		rc := readBlob(t, store, sid)
		defer rc.Close()
		got, err := DecodeAndVerify(rc, recDesc.SHA256)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !got.SHA256Verified {
			t.Errorf("expected SHA256Verified=true for matching digest")
		}
		if got.SHA256 != recDesc.SHA256 {
			t.Errorf("sha mismatch: got %s want %s", got.SHA256, recDesc.SHA256)
		}
		if got.Truncated {
			t.Errorf("expected Truncated=false")
		}
		if len(got.Frames) != 5 {
			t.Fatalf("expected 5 frames, got %d", len(got.Frames))
		}
		if got.Frames[1].Direction != "input" || string(got.Frames[1].Payload) != "ls -la\r" {
			t.Errorf("frame[1] = %+v", got.Frames[1])
		}
		if got.Bytes != recDesc.Bytes {
			t.Errorf("bytes: got %d want %d", got.Bytes, recDesc.Bytes)
		}
	})

	t.Run("tamper detected via wrong digest", func(t *testing.T) {
		rc := readBlob(t, store, sid)
		defer rc.Close()
		got, err := DecodeAndVerify(rc, "deadbeef")
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.SHA256Verified {
			t.Errorf("expected SHA256Verified=false for non-matching digest")
		}
	})

	t.Run("empty expected digest leaves verified false but computes sha", func(t *testing.T) {
		rc := readBlob(t, store, sid)
		defer rc.Close()
		got, err := DecodeAndVerify(rc, "")
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.SHA256Verified {
			t.Errorf("expected SHA256Verified=false with empty expected digest")
		}
		if got.SHA256 == "" {
			t.Errorf("expected a computed sha even without an expected digest")
		}
	})

	t.Run("case-insensitive digest comparison", func(t *testing.T) {
		rc := readBlob(t, store, sid)
		defer rc.Close()
		got, err := DecodeAndVerify(rc, strings.ToUpper(recDesc.SHA256))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !got.SHA256Verified {
			t.Errorf("expected verified=true for upper-cased digest")
		}
	})
}

func TestDecodeAndVerifyTruncated(t *testing.T) {
	t.Parallel()
	const sid = "22222222-2222-2222-2222-222222222222"
	// A tiny cap forces the recorder to truncate; the descriptor records it.
	store, recDesc := buildRecording(t, sid, 64, []struct {
		dir     Direction
		payload string
	}{
		{DirOutput, strings.Repeat("A", 200)},
		{DirOutput, strings.Repeat("B", 200)},
	})
	if !recDesc.Truncated {
		t.Skip("recorder did not truncate at this cap; nothing to assert")
	}
	rc := readBlob(t, store, sid)
	defer rc.Close()
	got, err := DecodeAndVerify(rc, recDesc.SHA256)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// A truncation MARKER frame is well-formed, so the stored bytes decode
	// cleanly; the important guarantee is that the digest still verifies and the
	// frames decoded are returned.
	if !got.SHA256Verified {
		t.Errorf("expected digest to verify over the truncated-but-complete bytes")
	}
	if len(got.Frames) == 0 {
		t.Errorf("expected at least one decoded frame")
	}
}

func TestDecodeAndVerifyNilReader(t *testing.T) {
	t.Parallel()
	if _, err := DecodeAndVerify(nil, ""); err == nil {
		t.Fatalf("expected error for nil reader")
	}
}

func TestDecodeAndVerifyCorruptHeader(t *testing.T) {
	t.Parallel()
	// A 3-byte blob is shorter than a frame header: ParseReplay reports
	// io.ErrUnexpectedEOF, which DecodeAndVerify treats as a truncated (still
	// usable) recording rather than a hard error.
	got, err := DecodeAndVerify(strings.NewReader("abc"), "")
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if !got.Truncated {
		t.Errorf("expected Truncated=true for a short blob")
	}
}

func TestExtractKeystrokeText(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		frames []ReplayFrame
		want   string
	}{
		{
			name: "only input frames are mined",
			frames: []ReplayFrame{
				{Direction: "control", Payload: []byte("session opened")},
				{Direction: "input", Payload: []byte("SELECT 1;\r")},
				{Direction: "output", Payload: []byte("secret-result-do-not-index")},
			},
			want: "SELECT 1;",
		},
		{
			name: "backspace deletes the previous rune",
			frames: []ReplayFrame{
				{Direction: "input", Payload: []byte("rm -rf /tnp\x7f\x7fmp\r")},
			},
			want: "rm -rf /tmp",
		},
		{
			name: "CSI arrow-key escape sequences are dropped",
			frames: []ReplayFrame{
				{Direction: "input", Payload: []byte("ls\x1b[A\x1b[B done\r")},
			},
			want: "ls done",
		},
		{
			name: "CR and LF split lines",
			frames: []ReplayFrame{
				{Direction: "input", Payload: []byte("a\rb\nc")},
			},
			want: "a\nb\nc",
		},
		{
			name: "tab becomes a space",
			frames: []ReplayFrame{
				{Direction: "input", Payload: []byte("a\tb")},
			},
			want: "a b",
		},
		{
			name: "CRLF coalesces into a single line break",
			frames: []ReplayFrame{
				{Direction: "input", Payload: []byte("echo hi\r\nls\r\n")},
			},
			want: "echo hi\nls",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ExtractKeystrokeText(tt.frames, 0)
			if got != tt.want {
				t.Errorf("ExtractKeystrokeText = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractKeystrokeTextCapped(t *testing.T) {
	t.Parallel()
	frames := []ReplayFrame{{Direction: "input", Payload: []byte(strings.Repeat("x", 100))}}
	got := ExtractKeystrokeText(frames, 10)
	if len(got) > 10 {
		t.Errorf("expected cap to 10 bytes, got %d", len(got))
	}
}

// sanity: the decode helper must not blow up on a genuinely empty recording.
func TestDecodeAndVerifyEmpty(t *testing.T) {
	t.Parallel()
	got, err := DecodeAndVerify(strings.NewReader(""), "")
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Frames) != 0 {
		t.Errorf("expected no frames, got %d", len(got.Frames))
	}
}
