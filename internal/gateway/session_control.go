package gateway

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// reconcileOrphanSession closes a session whose connect token was already
// redeemed — RedeemConnectToken atomically consumes the one-shot token and
// marks the session "active" — but whose proxy never started. This happens when
// a post-auth step fails before the normal cleanup defers are registered: an
// SSH handshake error after PasswordCallback succeeded, or a token presented to
// the wrong protocol listener. Without it the row would stay "active" forever
// with no proxy attached and the irreplaceable token already spent. It runs on
// a fresh timeout context detached from ctx so it still completes if ctx was
// already cancelled.
func reconcileOrphanSession(ctx context.Context, sessions *pam.SessionManager, session *models.PAMSession, logPrefix string) {
	if sessions == nil || session == nil {
		return
	}
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := sessions.CloseSession(closeCtx, session.WorkspaceID, session.ID); err != nil {
		logger.Warnf(ctx, "%s: reconcile orphaned session %s: %v", logPrefix, session.ID, err)
	}
}

// credUser resolves the upstream username for a leased session. It prefers the
// target's configured Username and falls back to the secret's, matching the
// existing Postgres and MySQL handlers so every protocol proxy resolves the
// upstream identity the same way. Centralised here so the new RDP/VNC/Mongo/
// Redis/MSSQL/Web handlers cannot drift from that convention.
func credUser(leased *pam.LeasedSession) string {
	if leased.Target.Username != "" {
		return leased.Target.Username
	}
	return leased.Secret.Username
}

// lockedWriter serializes concurrent writes to an underlying io.Writer with a
// mutex. The steady-state proxy for the request/response protocols (Redis,
// MongoDB) runs two goroutines that both write to the operator connection — one
// copying upstream replies, the other injecting locally-generated deny replies
// when a command is gated. A raw net.Conn does not serialize concurrent Write
// calls, so without this wrapper the bytes of a deny frame and an upstream
// reply frame could interleave on the wire and corrupt the stream. Every write
// to the operator in those handlers goes through one shared lockedWriter so a
// whole frame is emitted atomically relative to the other goroutine.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// newLockedWriter wraps w so concurrent Write calls are mutually exclusive.
func newLockedWriter(w io.Writer) *lockedWriter { return &lockedWriter{w: w} }

// Write implements io.Writer, holding the mutex for the duration of the
// underlying write so a single Write is emitted without interleaving.
func (lw *lockedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.w.Write(p)
}

// SessionHub tracks the privileged sessions currently proxied by this gateway
// process so an admin can take over: live-monitor the streamed I/O or terminate
// the connection outright. It is the in-process half of the takeover feature;
// the durable session state lives in the database (pam.SessionManager).
//
// SessionHub satisfies the pam.LiveController contract (Terminate), wired
// without an import cycle because pam declares that interface and the gateway
// implements it.
type SessionHub struct {
	mu       sync.Mutex
	sessions map[uuid.UUID]*hubEntry
}

type hubEntry struct {
	workspaceID uuid.UUID
	subject     string
	recorder    *IORecorder
	cancel      context.CancelFunc
	startedAt   time.Time
}

// NewSessionHub builds an empty hub.
func NewSessionHub() *SessionHub {
	return &SessionHub{sessions: make(map[uuid.UUID]*hubEntry)}
}

// Register adds an active session. cancel severs the proxied connection when an
// admin terminates it; recorder is the session's live recording, which an admin
// monitor subscribes to. The returned deregister func MUST be deferred by the
// handler so the session leaves the hub on teardown.
func (h *SessionHub) Register(sessionID, workspaceID uuid.UUID, subject string, recorder *IORecorder, cancel context.CancelFunc) (deregister func()) {
	h.mu.Lock()
	h.sessions[sessionID] = &hubEntry{
		workspaceID: workspaceID,
		subject:     subject,
		recorder:    recorder,
		cancel:      cancel,
		startedAt:   time.Now(),
	}
	h.mu.Unlock()
	return func() {
		h.mu.Lock()
		delete(h.sessions, sessionID)
		h.mu.Unlock()
	}
}

// Terminate severs the live connection for sessionID. It returns true when the
// session was active in this process. The cancel runs outside the lock so a
// slow connection teardown cannot block other hub operations.
func (h *SessionHub) Terminate(sessionID uuid.UUID) bool {
	h.mu.Lock()
	entry, ok := h.sessions[sessionID]
	h.mu.Unlock()
	if !ok {
		return false
	}
	if entry.recorder != nil {
		entry.recorder.Annotate("[session terminated by administrator]")
	}
	if entry.cancel != nil {
		entry.cancel()
	}
	return true
}

// Monitor attaches a live monitor to an active session, returning a detach func
// and whether the session was found. An admin takeover UI calls this to watch
// the streamed transcript in real time.
func (h *SessionHub) Monitor(sessionID uuid.UUID, m LiveMonitor) (detach func(), ok bool) {
	h.mu.Lock()
	entry, found := h.sessions[sessionID]
	h.mu.Unlock()
	if !found || entry.recorder == nil {
		return func() {}, false
	}
	return entry.recorder.AddMonitor(m), true
}

// ActiveSession is a snapshot of one live session for an admin listing.
type ActiveSession struct {
	SessionID   uuid.UUID
	WorkspaceID uuid.UUID
	Subject     string
	StartedAt   time.Time
}

// ActiveInWorkspace lists the sessions this process is currently proxying for a
// workspace, so an admin sees only their tenant's live sessions.
func (h *SessionHub) ActiveInWorkspace(workspaceID uuid.UUID) []ActiveSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]ActiveSession, 0)
	for id, e := range h.sessions {
		if e.workspaceID != workspaceID {
			continue
		}
		out = append(out, ActiveSession{
			SessionID:   id,
			WorkspaceID: e.workspaceID,
			Subject:     e.subject,
			StartedAt:   e.startedAt,
		})
	}
	return out
}
