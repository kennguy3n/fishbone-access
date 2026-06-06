package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"
)

// Direction labels one side of a recorded privileged session. A replay tool
// reconstructs the terminal/wire transcript by ordering frames on their
// timestamp and colouring each by direction.
type Direction byte

const (
	// DirInput is bytes flowing from the operator's client toward the target
	// (keystrokes, SQL statements, stdin).
	DirInput Direction = 'I'
	// DirOutput is bytes flowing from the target back to the operator (program
	// output, query results, stdout).
	DirOutput Direction = 'O'
	// DirControl is an out-of-band annotation the proxy injects itself (session
	// banners, policy-deny notices, takeover/termination markers) rather than
	// payload copied between the two peers.
	DirControl Direction = 'C'
)

// frameHeaderLen is the fixed prefix on every recorded frame:
// 1 byte direction + 8 bytes big-endian unix-nanos + 4 bytes big-endian length.
const frameHeaderLen = 1 + 8 + 4

// ReplayStore is the durable sink an IORecorder flushes a finished session's
// recording to. Implementations exist for the local filesystem
// (FilesystemReplayStore), S3-compatible object storage (S3ReplayStore), and
// in-memory test doubles (MemoryReplayStore). Callers never build the storage
// key by hand — ReplayKey is the single source of the canonical layout so the
// replay UI and the recorder always agree.
type ReplayStore interface {
	// PutReplay stores the full replay payload for sessionID. r yields the
	// complete recording; implementations may read it in one shot.
	PutReplay(ctx context.Context, sessionID string, r io.Reader) error
}

// ReplayKey returns the canonical storage key for a session's recording. Keep
// every store and reader anchored on this so a session recorded to the
// filesystem today can be migrated to S3 under the same key tomorrow.
func ReplayKey(sessionID string) string {
	return fmt.Sprintf("sessions/%s/replay.bin", sessionID)
}

// LiveMonitor receives a copy of every frame as it is recorded, enabling an
// admin "takeover" to watch an active privileged session in real time. The
// recorder fans out to monitors on a best-effort basis: a slow or blocked
// monitor MUST NOT stall the proxied session, so OnFrame is expected to be
// non-blocking (the session-control hub buffers per-subscriber).
type LiveMonitor interface {
	OnFrame(dir Direction, at time.Time, payload []byte)
}

// IORecorder captures both directions of a proxied session into a single
// framed, timestamp-ordered byte stream, then flushes it to a ReplayStore when
// the session ends. It is safe for concurrent use: the input-copy goroutine and
// the output-copy goroutine record into the same recorder without external
// locking.
//
// To bound memory on a long-lived session the recorder caps the buffered
// recording at maxBytes; once the cap is hit further payload is dropped and the
// recording is marked truncated (a control frame notes the truncation), but
// proxying continues uninterrupted — recording must never become a denial of
// service against the session itself.
type IORecorder struct {
	sessionID string
	maxBytes  int

	mu        sync.Mutex
	buf       bytes.Buffer
	truncated bool
	closed    bool
	monitors  map[int]LiveMonitor
	nextMonID int

	now func() time.Time
}

// NewIORecorder builds a recorder for sessionID. maxBytes caps the buffered
// recording (<= 0 selects a 64 MiB default); the cap protects the gateway from
// an unbounded session exhausting memory.
func NewIORecorder(sessionID string, maxBytes int) *IORecorder {
	if maxBytes <= 0 {
		maxBytes = 64 << 20
	}
	return &IORecorder{
		sessionID: sessionID,
		maxBytes:  maxBytes,
		monitors:  make(map[int]LiveMonitor),
		now:       time.Now,
	}
}

// Record appends one framed payload in the given direction. A zero-length
// payload is ignored. It never returns an error: recording is best-effort
// relative to the session, so a full buffer drops bytes rather than failing the
// proxy.
func (r *IORecorder) Record(dir Direction, payload []byte) {
	if len(payload) == 0 {
		return
	}
	at := r.now()

	r.mu.Lock()
	if !r.closed {
		r.appendLocked(dir, at, payload)
	}
	monitors := make([]LiveMonitor, 0, len(r.monitors))
	for _, m := range r.monitors {
		monitors = append(monitors, m)
	}
	r.mu.Unlock()

	// Fan out to live monitors outside the lock: a takeover watcher must never
	// be able to block the proxied byte path.
	for _, m := range monitors {
		m.OnFrame(dir, at, payload)
	}
}

// appendLocked writes one frame to the buffer, honouring the size cap. Caller
// holds r.mu.
func (r *IORecorder) appendLocked(dir Direction, at time.Time, payload []byte) {
	if r.truncated {
		return
	}
	if r.buf.Len()+frameHeaderLen+len(payload) > r.maxBytes {
		r.truncated = true
		r.writeFrameLocked(DirControl, at, []byte("[recording truncated: size cap reached]"))
		return
	}
	r.writeFrameLocked(dir, at, payload)
}

// writeFrameLocked emits the fixed header followed by the payload. Caller holds
// r.mu. bytes.Buffer.Write never returns a non-nil error (it panics on OOM), so
// the writes are unchecked by design.
func (r *IORecorder) writeFrameLocked(dir Direction, at time.Time, payload []byte) {
	var hdr [frameHeaderLen]byte
	hdr[0] = byte(dir)
	binary.BigEndian.PutUint64(hdr[1:9], uint64(at.UnixNano()))
	binary.BigEndian.PutUint32(hdr[9:13], uint32(len(payload)))
	r.buf.Write(hdr[:])
	r.buf.Write(payload)
}

// TeeReader returns a reader that yields the same bytes as src while recording
// everything read from it in direction dir. Use it to wrap the target→client
// (output) and client→target (input) halves of a proxied stream.
func (r *IORecorder) TeeReader(dir Direction, src io.Reader) io.Reader {
	return &teeRecorder{rec: r, dir: dir, src: src}
}

// AddMonitor registers a live monitor and returns a function that removes it.
// Used by session takeover to attach/detach an admin watcher mid-session.
func (r *IORecorder) AddMonitor(m LiveMonitor) (remove func()) {
	r.mu.Lock()
	id := r.nextMonID
	r.nextMonID++
	r.monitors[id] = m
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		delete(r.monitors, id)
		r.mu.Unlock()
	}
}

// Annotate records a control-direction frame. The proxy uses it to mark
// policy-deny events, step-up prompts, and admin termination inside the replay
// so the transcript explains itself.
func (r *IORecorder) Annotate(note string) {
	r.Record(DirControl, []byte(note))
}

// Bytes returns a copy of the recording captured so far. Primarily for tests
// and for callers that flush via a path other than Flush.
func (r *IORecorder) Bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]byte, r.buf.Len())
	copy(out, r.buf.Bytes())
	return out
}

// Truncated reports whether the size cap was hit and some payload dropped.
func (r *IORecorder) Truncated() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.truncated
}

// Flush writes the recording to store under ReplayKey(sessionID) and marks the
// recorder closed (subsequent Record calls are ignored). It is idempotent-safe
// to call once at session end. A nil store is a no-op close, so a deployment
// with recording disabled still tears the recorder down cleanly.
func (r *IORecorder) Flush(ctx context.Context, store ReplayStore) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	snapshot := make([]byte, r.buf.Len())
	copy(snapshot, r.buf.Bytes())
	r.mu.Unlock()

	if store == nil {
		return nil
	}
	if err := store.PutReplay(ctx, r.sessionID, bytes.NewReader(snapshot)); err != nil {
		return fmt.Errorf("gateway: flush replay %s: %w", r.sessionID, err)
	}
	return nil
}

// teeRecorder records every byte it passes through in one direction.
type teeRecorder struct {
	rec *IORecorder
	dir Direction
	src io.Reader
}

func (t *teeRecorder) Read(p []byte) (int, error) {
	n, err := t.src.Read(p)
	if n > 0 {
		t.rec.Record(t.dir, p[:n])
	}
	return n, err
}
