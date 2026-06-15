package webaccess

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// sanitizeCommandText makes an operator command/statement safe to persist in
// the Postgres TEXT command-log and audit-chain columns. Two byte classes a raw
// terminal or a hostile client can inject are fatal to those writes: a NUL
// (0x00), which Postgres rejects outright in TEXT, and any invalid UTF-8
// sequence (e.g. a lone continuation byte from a torn multibyte keystroke or
// paste), which Postgres also refuses as "invalid byte sequence for encoding
// UTF8". Such a write failure must never bubble up as a fail-closed teardown
// with a misleading "command policy unavailable" — a single stray input byte
// cannot be allowed to kill a governed session — so we drop NULs and coerce the
// remainder to valid UTF-8 before the string reaches LogCommand. Well-formed
// ASCII/UTF-8 input is returned byte-for-byte, leaving policy/audit semantics
// unchanged. Only the audited string is sanitized; the raw operator bytes still
// stream to the upstream PTY untouched, so the shell sees exactly what was sent.
func sanitizeCommandText(s string) string {
	if strings.IndexByte(s, 0) >= 0 {
		s = strings.ReplaceAll(s, "\x00", "")
	}
	return strings.ToValidUTF8(s, "")
}

// WebSocket message-type discriminators carried in the JSON control frames.
// Raw terminal bytes (SSH) travel as binary frames with no JSON envelope; every
// other message is a JSON text frame tagged with one of these.
const (
	// msgHello is the client's first frame on any session: it carries the
	// one-shot connect token and, for SSH, the initial terminal dimensions.
	msgHello = "hello"
	// msgReady is the server's acknowledgement after the token is redeemed and
	// the upstream is connected: it describes the governed session to the UI
	// (target, subject, recording/policy banner, lease expiry).
	msgReady = "ready"
	// msgInput carries operator keystrokes for SSH when sent as JSON (base64);
	// the browser normally sends keystrokes as raw binary frames instead, but
	// the JSON form keeps the protocol usable from a non-binary client and from
	// tests.
	msgInput = "input"
	// msgResize is an SSH terminal resize (cols/rows) → upstream window-change.
	msgResize = "resize"
	// msgQuery is a database-console statement to evaluate and execute.
	msgQuery = "query"
	// msgResult is the result set (or affected-row summary) for a query.
	msgResult = "result"
	// msgError is a non-fatal error surfaced to the operator (policy deny,
	// query error). It does not by itself close the session.
	msgError = "error"
	// msgStatus is a session lifecycle/state banner (paused, resumed, closed,
	// terminated) so the UI can reflect admin takeover and teardown.
	msgStatus = "status"
	// msgPing is a client heartbeat carrying the client's monotonic timestamp;
	// the server echoes it back unchanged in a msgPong so the UI can measure the
	// live round-trip latency of the governed link. A ping deliberately does NOT
	// refresh the idle clock, so a backgrounded tab's heartbeat cannot keep an
	// abandoned session alive past its idle timeout.
	msgPing = "ping"
	// msgPong is the server's immediate reply to a msgPing, echoing the client
	// timestamp so the browser computes RTT without a server clock dependency.
	msgPong = "pong"
)

// clientMessage is the union of every control frame the browser sends. Only the
// fields relevant to a given Type are populated.
type clientMessage struct {
	Type string `json:"type"`
	// Token is the one-shot PAM connect token (msgHello only).
	Token string `json:"token,omitempty"`
	// Cols/Rows are terminal dimensions (msgHello, msgResize).
	Cols int `json:"cols,omitempty"`
	Rows int `json:"rows,omitempty"`
	// Data is base64 operator input for the JSON keystroke form (msgInput).
	Data string `json:"data,omitempty"`
	// SQL is the statement text for the database console (msgQuery).
	SQL string `json:"sql,omitempty"`
	// TS is the client's monotonic timestamp (ms) for a heartbeat (msgPing); the
	// server echoes it back so the browser computes round-trip latency.
	TS int64 `json:"ts,omitempty"`
}

// pongMessage echoes a heartbeat's client timestamp back so the UI can derive a
// live latency reading for the governed link.
type pongMessage struct {
	Type string `json:"type"`
	TS   int64  `json:"ts"`
}

// readyMessage describes the governed session to the UI once it is live.
type readyMessage struct {
	Type           string `json:"type"`
	SessionID      string `json:"session_id"`
	Protocol       string `json:"protocol"`
	TargetName     string `json:"target_name"`
	TargetAddress  string `json:"target_address"`
	Subject        string `json:"subject"`
	Recording      bool   `json:"recording"`
	PolicyGoverned bool   `json:"policy_governed"`
	// LeaseExpiresAt is RFC3339 when the authorising lease (and thus the
	// session) expires, so the UI can show a live countdown; empty for the
	// legacy direct-mint path with no lease window.
	LeaseExpiresAt string `json:"lease_expires_at,omitempty"`
}

// queryColumn names one column in a result set.
type queryColumn struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

// resultMessage is the database console's answer to one statement. Either Rows
// (a SELECT-style result) or Command/RowsAffected (a write) is meaningful.
type resultMessage struct {
	Type         string        `json:"type"`
	Columns      []queryColumn `json:"columns,omitempty"`
	Rows         [][]*string   `json:"rows,omitempty"`
	Command      string        `json:"command,omitempty"`
	RowsAffected int64         `json:"rows_affected"`
	ElapsedMs    int64         `json:"elapsed_ms"`
	Truncated    bool          `json:"truncated,omitempty"`
}

// errorMessage is a non-fatal operator-facing error (policy deny, query error).
type errorMessage struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	// Denied is true when the error is a command-policy denial (vs. an upstream
	// or syntax error), so the UI can style it distinctly.
	Denied bool `json:"denied,omitempty"`
}

// statusMessage reports a session lifecycle transition to the UI.
type statusMessage struct {
	Type   string `json:"type"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// Session lifecycle states surfaced in statusMessage.State.
const (
	statePaused     = "paused"
	stateResumed    = "resumed"
	stateClosed     = "closed"
	stateTerminated = "terminated"
)

// wsConn is the minimal WebSocket surface the bridge needs. *websocket.Conn
// satisfies it; declaring it as an interface keeps the bridge testable with an
// in-memory double and free of a hard gorilla import at the call sites.
type wsConn interface {
	ReadMessage() (messageType int, p []byte, err error)
	WriteMessage(messageType int, data []byte) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	Close() error
}

// wsSender serializes all writes to a WebSocket connection. gorilla forbids
// concurrent writers, but the bridge fans out from several goroutines (SSH
// stdout + stderr copy loops, control/status frames), so every outbound frame
// goes through this one mutex-guarded sender, each bounded by a write deadline
// so a stuck browser socket cannot wedge a copy goroutine forever.
type wsSender struct {
	mu           sync.Mutex
	conn         wsConn
	writeTimeout time.Duration
	closed       bool
}

func newWSSender(conn wsConn, writeTimeout time.Duration) *wsSender {
	if writeTimeout <= 0 {
		writeTimeout = 10 * time.Second
	}
	return &wsSender{conn: conn, writeTimeout: writeTimeout}
}

// binary sends a raw binary frame (SSH terminal output).
func (s *wsSender) binary(p []byte) error {
	return s.write(websocket.BinaryMessage, p)
}

// json marshals v and sends it as a text frame.
func (s *wsSender) json(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.write(websocket.TextMessage, b)
}

func (s *wsSender) write(messageType int, p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return websocket.ErrCloseSent
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	return s.conn.WriteMessage(messageType, p)
}

// markClosed stops further writes after teardown so a late copy-goroutine flush
// does not race a closing connection.
func (s *wsSender) markClosed() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
}
