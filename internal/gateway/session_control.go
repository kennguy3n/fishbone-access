package gateway

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

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
