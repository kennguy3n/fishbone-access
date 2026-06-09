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

	// pauseCond gates the operator→target (DirInput) byte path for the live
	// soft-pause control. While paused is true, the input path blocks in
	// waitWhilePaused before delivering bytes upstream, so an operator's
	// keystrokes/statements are held (back-pressured in the kernel socket
	// buffer — buffered, not dropped) until an operator resumes or the session
	// is torn down. aborted releases blocked waiters on terminate so a paused
	// session can still be killed; closed releases them on normal flush; a
	// cancelled session context (see watchContext) also releases them so a
	// session that ends naturally (upstream hangs up) while paused cannot leak
	// the parked input goroutine.
	pauseCond *sync.Cond
	paused    bool
	aborted   bool

	now func() time.Time
}

// NewIORecorder builds a recorder for sessionID, bound to the session's
// context. maxBytes caps the buffered recording (<= 0 selects a 64 MiB
// default); the cap protects the gateway from an unbounded session exhausting
// memory.
//
// ctx is the session context: when it is cancelled (admin terminate, upstream
// hang-up, or gateway shutdown) the recorder releases any input read parked on
// the soft-pause gate, so a paused session that ends for any reason cannot
// strand its input-copy goroutine. A nil or non-cancellable context (e.g.
// context.Background() in unit tests) simply installs no watcher.
func NewIORecorder(ctx context.Context, sessionID string, maxBytes int) *IORecorder {
	if maxBytes <= 0 {
		maxBytes = 64 << 20
	}
	r := &IORecorder{
		sessionID: sessionID,
		maxBytes:  maxBytes,
		monitors:  make(map[int]LiveMonitor),
		now:       time.Now,
	}
	r.pauseCond = sync.NewCond(&r.mu)
	r.watchContext(ctx)
	return r
}

// watchContext releases the soft-pause gate when ctx is cancelled. The session
// context is cancelled on every teardown path — admin terminate (hub cancel),
// natural upstream close (the copy goroutine's deferred cancel), and gateway
// shutdown (parent cancel) — so this is the single mechanism that guarantees a
// paused session never strands its parked input goroutine, independent of which
// path tore the session down. The watcher goroutine exits as soon as ctx is
// done, so it cannot itself leak. A context with a nil Done channel (the
// never-cancellable context.Background/TODO used by unit tests) installs no
// watcher.
func (r *IORecorder) watchContext(ctx context.Context) {
	if ctx == nil || ctx.Done() == nil {
		return
	}
	go func() {
		<-ctx.Done()
		r.mu.Lock()
		r.aborted = true
		r.pauseCond.Broadcast()
		r.mu.Unlock()
	}()
}

// Pause raises the soft-pause gate: the operator→target byte path blocks until
// Resume, Interrupt, or Flush. It is idempotent and records a control frame so
// the replay transcript shows exactly when the operator was frozen. Output
// (target→operator) is intentionally NOT gated — a watching admin keeps seeing
// the live screen — only operator input is withheld.
func (r *IORecorder) Pause() {
	r.mu.Lock()
	already := r.paused
	r.paused = true
	r.mu.Unlock()
	if !already {
		r.Annotate("[session paused by administrator]")
	}
}

// Resume lowers the soft-pause gate and wakes any blocked input read. It is
// idempotent.
func (r *IORecorder) Resume() {
	r.mu.Lock()
	was := r.paused
	r.paused = false
	r.pauseCond.Broadcast()
	r.mu.Unlock()
	if was {
		r.Annotate("[session resumed by administrator]")
	}
}

// IsPaused reports whether the input gate is currently raised.
func (r *IORecorder) IsPaused() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.paused
}

// Interrupt permanently releases the pause gate without resuming normal flow:
// it wakes any blocked input read so a paused session can be torn down by a
// terminate. After Interrupt the gate never blocks again (the session is going
// away). Idempotent.
func (r *IORecorder) Interrupt() {
	r.mu.Lock()
	r.aborted = true
	r.pauseCond.Broadcast()
	r.mu.Unlock()
}

// waitWhilePaused blocks the calling (input-copy) goroutine while the gate is
// raised, returning once the session is resumed, interrupted, closed, or its
// context is cancelled (watchContext sets aborted).
func (r *IORecorder) waitWhilePaused() {
	r.mu.Lock()
	for r.paused && !r.aborted && !r.closed {
		r.pauseCond.Wait()
	}
	r.mu.Unlock()
}

// WaitWhilePaused blocks the calling goroutine while the soft-pause gate is
// raised. It is the explicit gate for the protocol-parsing handlers (Postgres,
// MySQL, Redis, MongoDB, MSSQL, VNC, RDP, Web), which read structured operator
// messages in their own loops rather than copying a raw byte stream: each calls
// this at the top of its operator-read loop so that, while an administrator has
// paused the session, the handler stops pulling the next operator
// command/message and nothing further reaches the upstream target. It returns
// immediately (does not block) once the session is resumed, terminated, or torn
// down, so a paused session is never wedged. The raw byte-stream handlers (SSH,
// k8s-exec) instead compose GateReader/TeeReader, which call this internally.
func (r *IORecorder) WaitWhilePaused() { r.waitWhilePaused() }

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
		// The marker is always emitted so the transcript records that bytes were
		// dropped (a silent stop would be worse for audit). buf.Len() was kept
		// <= maxBytes by the prior frame, so the final buffer is bounded by
		// maxBytes + this marker frame — a fixed, content-independent overshoot,
		// not attacker-amplifiable. The cap is a soft growth guard, not a hard
		// allocation limit, so we don't reserve headroom for it.
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
// (output) and client→target (input) halves of a proxied stream. A DirInput
// tee also honours the soft-pause gate (it blocks before reading while paused).
func (r *IORecorder) TeeReader(dir Direction, src io.Reader) io.Reader {
	return &teeRecorder{rec: r, dir: dir, src: src}
}

// GateReader wraps src so each Read blocks while the session is soft-paused,
// without itself recording. The SSH handler composes it around the operator
// channel because that handler already records (and command-gates) operator
// input via its shellCommandScanner — routing the bytes through TeeReader as
// well would double-record them. The pause semantics are identical to the
// DirInput TeeReader: while paused no operator bytes are pulled from src, so
// nothing reaches the upstream target until an operator resumes or the session
// is torn down.
func (r *IORecorder) GateReader(src io.Reader) io.Reader {
	return &pauseGateReader{rec: r, src: src}
}

// pauseGateReader blocks on the soft-pause gate before each read but records
// nothing (the caller records). See GateReader.
type pauseGateReader struct {
	rec *IORecorder
	src io.Reader
}

func (g *pauseGateReader) Read(p []byte) (int, error) {
	g.rec.waitWhilePaused()
	return g.src.Read(p)
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
	// Release any input read still blocked on the pause gate so a paused
	// session does not leak a goroutine when it is flushed/torn down.
	r.pauseCond.Broadcast()
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
	// Gate only the operator→target (input) direction: while the session is
	// paused this blocks before pulling the next operator bytes, so nothing the
	// operator types reaches upstream until an operator resumes. Output frames
	// keep flowing so a watching admin sees the live screen throughout.
	if t.dir == DirInput {
		t.rec.waitWhilePaused()
	}
	n, err := t.src.Read(p)
	if n > 0 {
		t.rec.Record(t.dir, p[:n])
	}
	return n, err
}
