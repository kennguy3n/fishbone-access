package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"
)

// memReplayStore is an in-memory ReplayStore + ReplayReader for round-trip
// tests: it captures what Flush writes and serves it back to ParseReplay,
// exercising the exact bytes the production filesystem/S3 stores would.
type memReplayStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemReplayStore() *memReplayStore { return &memReplayStore{data: map[string][]byte{}} }

func (m *memReplayStore) PutReplay(_ context.Context, sessionID string, r io.Reader) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[sessionID] = b
	return nil
}

func (m *memReplayStore) GetReplay(_ context.Context, sessionID string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.data[sessionID]
	if !ok {
		return nil, io.EOF
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// TestRecorderReplayRoundTrip records both directions, flushes to a store, then
// parses the recording back and asserts frames round-trip with direction,
// payload, and capture order preserved.
func TestRecorderReplayRoundTrip(t *testing.T) {
	rec := NewIORecorder(context.Background(), "sess-1", 0)

	rec.Record(DirInput, []byte("whoami\n"))
	rec.Record(DirOutput, []byte("root\n"))
	rec.Record(DirInput, []byte("exit\n"))

	store := newMemReplayStore()
	if err := rec.Flush(context.Background(), store); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	rc, err := store.GetReplay(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("GetReplay: %v", err)
	}
	defer rc.Close()
	frames, err := ParseReplay(rc)
	if err != nil {
		t.Fatalf("ParseReplay: %v", err)
	}
	if len(frames) != 3 {
		t.Fatalf("want 3 frames, got %d", len(frames))
	}
	want := []struct {
		dir     string
		payload string
	}{
		{"input", "whoami\n"},
		{"output", "root\n"},
		{"input", "exit\n"},
	}
	for idx, w := range want {
		if frames[idx].Direction != w.dir || string(frames[idx].Payload) != w.payload {
			t.Fatalf("frame %d: got (%q,%q), want (%q,%q)", idx, frames[idx].Direction, frames[idx].Payload, w.dir, w.payload)
		}
	}
	// Frames are timestamp-ordered as written.
	for idx := 1; idx < len(frames); idx++ {
		if frames[idx].At.Before(frames[idx-1].At) {
			t.Fatalf("frames out of order at %d", idx)
		}
	}
}

// TestParseReplayEmptyIsEmptyArray guards the replay API contract: an empty
// recording (a session opened then torn down before any I/O) must decode to a
// non-nil empty slice so it marshals to JSON [] rather than null. A null would
// crash the console's frames.length read.
func TestParseReplayEmptyIsEmptyArray(t *testing.T) {
	frames, err := ParseReplay(bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("ParseReplay(empty): %v", err)
	}
	if frames == nil {
		t.Fatalf("ParseReplay(empty) returned a nil slice; want non-nil empty slice")
	}
	if len(frames) != 0 {
		t.Fatalf("want 0 frames, got %d", len(frames))
	}
	b, err := json.Marshal(frames)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != "[]" {
		t.Fatalf("empty frames marshalled to %s, want []", b)
	}
}

// TestRecorderPauseGateBlocksInput proves the soft-pause gate holds
// operator→target (input) bytes while paused and releases them on resume, while
// output continues to flow to watchers throughout.
func TestRecorderPauseGateBlocksInput(t *testing.T) {
	rec := NewIORecorder(context.Background(), "sess-2", 0)

	// An input reader that yields one chunk; the TeeReader gates it on pause.
	src := bytes.NewReader([]byte("rm -rf /\n"))
	gated := rec.TeeReader(DirInput, src)

	rec.Pause()
	if !rec.IsPaused() {
		t.Fatal("recorder should report paused")
	}

	done := make(chan int, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := gated.Read(buf) // blocks while paused
		done <- n
	}()

	select {
	case <-done:
		t.Fatal("input read returned while paused; gate did not hold")
	case <-time.After(100 * time.Millisecond):
		// expected: still blocked
	}

	// Output keeps flowing while paused (a watching admin still sees the screen).
	rec.Record(DirOutput, []byte("are you sure?\n"))

	rec.Resume()
	select {
	case n := <-done:
		if n == 0 {
			t.Fatal("expected input bytes to flow after resume")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("input read did not unblock after resume")
	}
}

// TestRecorderInterruptReleasesPausedInput confirms Interrupt (used by
// terminate) releases a blocked input read so a paused session can still be
// torn down without leaking the proxy goroutine.
func TestRecorderInterruptReleasesPausedInput(t *testing.T) {
	rec := NewIORecorder(context.Background(), "sess-3", 0)
	src := bytes.NewReader([]byte("data"))
	gated := rec.TeeReader(DirInput, src)

	rec.Pause()
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 16)
		_, _ = gated.Read(buf)
		close(done)
	}()

	rec.Interrupt()
	select {
	case <-done:
		// released
	case <-time.After(2 * time.Second):
		t.Fatal("Interrupt did not release the paused input read")
	}
}

// TestWaitWhilePausedGatesAndReleases proves the explicit WaitWhilePaused gate
// — the one the protocol-parsing handlers (Postgres, MySQL, Redis, MongoDB,
// MSSQL, VNC, RDP, Web) call at the top of their operator-read loops — holds
// the caller while paused and releases it on resume. This is the regression
// guard for the soft-pause bug where only the k8s-exec byte-copy path (which
// gated via the DirInput TeeReader) was frozen while the eight message-framed
// protocols kept forwarding operator commands to their targets.
func TestWaitWhilePausedGatesAndReleases(t *testing.T) {
	rec := NewIORecorder(context.Background(), "sess-wait", 0)

	rec.Pause()
	released := make(chan struct{})
	go func() {
		rec.WaitWhilePaused() // blocks until resume/interrupt/ctx-cancel
		close(released)
	}()

	select {
	case <-released:
		t.Fatal("WaitWhilePaused returned while paused; the message-protocol gate did not hold")
	case <-time.After(100 * time.Millisecond):
		// expected: still parked at the gate
	}

	rec.Resume()
	select {
	case <-released:
		// expected: released once resumed
	case <-time.After(2 * time.Second):
		t.Fatal("WaitWhilePaused did not release after resume")
	}
}

// TestGateReaderGatesWithoutRecording proves GateReader (the SSH stdin path)
// holds operator bytes while paused and releases them on resume, and that it
// records nothing itself — the SSH handler records and command-gates stdin via
// its own scanner, so the gate must not double-record. It is part of the
// soft-pause regression set: SSH copies a raw byte stream via the standard
// library io.TeeReader, so before this gate its keystrokes reached the upstream
// shell even while an admin had paused the session.
func TestGateReaderGatesWithoutRecording(t *testing.T) {
	rec := NewIORecorder(context.Background(), "sess-gate", 0)
	src := bytes.NewReader([]byte("sudo rm -rf /\n"))
	gated := rec.GateReader(src)

	rec.Pause()
	done := make(chan int, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := gated.Read(buf) // blocks while paused
		done <- n
	}()

	select {
	case <-done:
		t.Fatal("GateReader read returned while paused; the SSH gate did not hold")
	case <-time.After(100 * time.Millisecond):
		// expected: still blocked
	}

	rec.Resume()
	select {
	case n := <-done:
		if n == 0 {
			t.Fatal("expected operator bytes to flow after resume")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GateReader did not unblock after resume")
	}

	// The gate records nothing itself (the caller records), so the recording
	// holds no input frame from it — proving GateReader is gate-only.
	store := newMemReplayStore()
	if err := rec.Flush(context.Background(), store); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	rc, err := store.GetReplay(context.Background(), "sess-gate")
	if err != nil {
		t.Fatalf("GetReplay: %v", err)
	}
	defer rc.Close()
	frames, err := ParseReplay(rc)
	if err != nil {
		t.Fatalf("ParseReplay: %v", err)
	}
	for _, f := range frames {
		if f.Direction == "input" {
			t.Fatalf("GateReader recorded an input frame %q; it must be gate-only", f.Payload)
		}
	}
}

// TestRecorderContextCancelReleasesPausedInput is the regression guard for the
// paused-session goroutine leak: when a session ends naturally while paused
// (the upstream hangs up, so the copy goroutine's deferred cancel fires) there
// is no Resume or Interrupt to wake the input goroutine parked on the gate.
// Binding the recorder to the session context must release it on cancel so the
// proxy's input-copy goroutine cannot be stranded forever.
func TestRecorderContextCancelReleasesPausedInput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := NewIORecorder(ctx, "sess-ctx", 0)
	src := bytes.NewReader([]byte("data"))
	gated := rec.TeeReader(DirInput, src)

	rec.Pause()
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 16)
		_, _ = gated.Read(buf) // parked on the gate, no resume/interrupt coming
		close(done)
	}()

	// Confirm it is actually parked before cancelling, so the test proves the
	// cancel (not some other path) released it.
	select {
	case <-done:
		t.Fatal("input read returned while paused before context cancel")
	case <-time.After(100 * time.Millisecond):
	}

	cancel() // session context ends, as on a natural upstream close
	select {
	case <-done:
		// released by the context watcher — no leak
	case <-time.After(2 * time.Second):
		t.Fatal("context cancel did not release the paused input read (goroutine leak)")
	}
}
