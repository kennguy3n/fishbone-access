package webaccess

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/kennguy3n/fishbone-access/internal/gateway"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// defaultTermCols/Rows back-fill terminal dimensions the browser omitted, so a
// PTY is always requested with a sane size.
const (
	defaultTermCols = 80
	defaultTermRows = 24
)

// runSSH opens an interactive PTY shell on the upstream and bridges it to the
// browser: upstream stdout/stderr are recorded and streamed as binary frames,
// operator keystrokes are recorded, command-gated, and (while not paused)
// written to the upstream shell, and resize control frames drive the upstream
// window. It blocks until the shell exits, the operator disconnects, or the
// session is cancelled (idle/terminate), then returns so the caller's teardown
// flushes the recording.
func (b *Bridge) runSSH(ctx context.Context, cancel context.CancelFunc, conn wsConn, sender *wsSender, leased *pam.LeasedSession, rec *gateway.IORecorder, hello clientMessage, activity *activityClock) {
	client, err := dialUpstreamSSH(leased, b.ca, b.dialTimeout)
	if err != nil {
		rec.Annotate(fmt.Sprintf("[upstream dial failed: %v]", err))
		_ = sender.json(errorMessage{Type: msgError, Message: "cannot reach target: " + sanitizeDialError(err)})
		logger.Warnf(ctx, "webaccess: dial upstream ssh %s: %v", leased.Target.Address, err)
		return
	}
	defer func() { _ = client.Close() }()

	sess, err := client.NewSession()
	if err != nil {
		rec.Annotate(fmt.Sprintf("[open upstream session failed: %v]", err))
		_ = sender.json(errorMessage{Type: msgError, Message: "cannot open shell on target"})
		return
	}
	defer func() { _ = sess.Close() }()

	cols, rows := hello.Cols, hello.Rows
	if cols <= 0 {
		cols = defaultTermCols
	}
	if rows <= 0 {
		rows = defaultTermRows
	}
	// Request a PTY so the upstream runs an interactive shell with job control,
	// line editing, and colour, exactly like a native ssh -t.
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := sess.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		_ = sender.json(errorMessage{Type: msgError, Message: "target rejected PTY request"})
		return
	}

	stdin, err := sess.StdinPipe()
	if err != nil {
		return
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return
	}
	if err := sess.Shell(); err != nil {
		_ = sender.json(errorMessage{Type: msgError, Message: "target rejected shell"})
		return
	}

	// The bridge's closeOnCancel goroutine closes the socket when the session
	// ends for any reason (shell exit, admin terminate, idle timeout), which
	// makes the blocking WebSocket read return so this input loop exits
	// promptly — after delivering a descriptive close status to the operator.

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); b.pumpOutput(ctx, sender, rec, stdout, activity) }()
	go func() { defer wg.Done(); b.pumpOutput(ctx, sender, rec, stderr, activity) }()

	// Wait for the shell to exit on its own and tear the session down.
	go func() {
		_ = sess.Wait()
		cancel()
	}()

	b.pumpSSHInput(ctx, cancel, conn, sender, leased.Session, rec, stdin, sess, activity)

	// Operator disconnected or session cancelled: stop the upstream so the
	// output pumps unblock, then join them before returning (so the recording
	// is complete when the caller flushes it).
	cancel()
	_ = sess.Close()
	wg.Wait()
}

// pumpOutput copies one upstream stream (stdout or stderr) to the browser as
// binary frames, recording every byte as session output and refreshing the
// idle clock.
func (b *Bridge) pumpOutput(ctx context.Context, sender *wsSender, rec *gateway.IORecorder, src io.Reader, activity *activityClock) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			rec.Record(gateway.DirOutput, chunk)
			activity.touch()
			if werr := sender.binary(chunk); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// pumpSSHInput reads operator frames and forwards keystrokes to the upstream
// shell. Binary frames are raw keystrokes; text frames are JSON control
// (resize, or base64 input). Every keystroke is recorded as input and scanned
// for newline-delimited commands evaluated against policy; a deny tears the
// session down (an interactive PTY cannot un-send a keystroke, so terminate is
// the only fail-closed enforcement, matching the native SSH proxy). While an
// admin has soft-paused the session no keystroke is forwarded, but output keeps
// flowing so the admin can watch live.
func (b *Bridge) pumpSSHInput(ctx context.Context, cancel context.CancelFunc, conn wsConn, sender *wsSender, session *models.PAMSession, rec *gateway.IORecorder, stdin io.WriteCloser, sess sshWindowChanger, activity *activityClock) {
	defer func() { _ = stdin.Close() }()
	scanner := &commandScanner{ctx: ctx, sessions: b.sessions, session: session, rec: rec, cancel: cancel, sender: sender}
	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		switch mt {
		case websocket.BinaryMessage:
			if !b.forwardKeystrokes(rec, scanner, stdin, data, activity) {
				return
			}
		case websocket.TextMessage:
			var msg clientMessage
			if json.Unmarshal(data, &msg) != nil {
				continue
			}
			switch msg.Type {
			case msgResize:
				cols, rows := msg.Cols, msg.Rows
				if cols <= 0 {
					cols = defaultTermCols
				}
				if rows <= 0 {
					rows = defaultTermRows
				}
				_ = sess.WindowChange(rows, cols)
			case msgInput:
				raw, derr := base64.StdEncoding.DecodeString(msg.Data)
				if derr != nil {
					continue
				}
				if !b.forwardKeystrokes(rec, scanner, stdin, raw, activity) {
					return
				}
			case msgPing:
				// Heartbeat: echo the client timestamp for an RTT reading. It is
				// deliberately not gated by the pause state and does not touch
				// the idle clock (so a heartbeat cannot keep an idle session
				// alive).
				_ = sender.json(pongMessage{Type: msgPong, TS: msg.TS})
			}
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// forwardKeystrokes applies the soft-pause gate, forwards the bytes to the
// upstream shell, then records and command-scans them. It returns false when
// the session should end (write failure or a policy deny in the scanner).
func (b *Bridge) forwardKeystrokes(rec *gateway.IORecorder, scanner *commandScanner, stdin io.Writer, data []byte, activity *activityClock) bool {
	// Block here while paused: no keystroke is pulled toward the upstream until
	// an admin resumes (or terminates, which releases the wait via Interrupt).
	rec.WaitWhilePaused()
	if _, err := stdin.Write(data); err != nil {
		return false
	}
	activity.touch()
	// Record + scan after forwarding, matching the native proxy's TeeReader
	// ordering (bytes reach the shell as typed; a deny then tears down).
	return scanner.feed(data)
}

// sshWindowChanger is the subset of *ssh.Session the input pump needs, declared
// as an interface so the pump is unit-testable without a live SSH server.
type sshWindowChanger interface {
	WindowChange(h, w int) error
}

// commandScanner records operator stdin and extracts newline-delimited commands
// for live policy evaluation on the interactive shell, mirroring the gateway's
// shellCommandScanner. On a deny it annotates the recording, tells the operator
// why, and cancels the session.
type commandScanner struct {
	ctx      context.Context
	sessions *pam.SessionManager
	session  *models.PAMSession
	rec      *gateway.IORecorder
	cancel   context.CancelFunc
	sender   *wsSender
	buf      []byte
}

// feed records and scans a chunk of operator input, returning false once a deny
// has cancelled the session.
func (s *commandScanner) feed(p []byte) bool {
	s.rec.Record(gateway.DirInput, p)
	for _, ch := range p {
		if ch == '\r' || ch == '\n' {
			if !s.flushLine() {
				return false
			}
			continue
		}
		// Cap the buffered line so a pathological no-newline stream cannot grow
		// memory without bound.
		if len(s.buf) < 4096 {
			s.buf = append(s.buf, ch)
		}
	}
	return true
}

func (s *commandScanner) flushLine() bool {
	cmd := sanitizeCommandText(strings.TrimSpace(string(s.buf)))
	s.buf = s.buf[:0]
	if cmd == "" {
		return true
	}
	decision, err := s.sessions.LogCommand(s.ctx, s.session, cmd)
	if err != nil || !decision.Allowed() {
		reason := decision.Reason
		if reason == "" {
			reason = "denied by command policy"
		}
		if err != nil {
			reason = "command policy unavailable"
		}
		s.rec.Annotate(fmt.Sprintf("[shell command %q %s: %s]", cmd, models.PAMDecisionDeny, reason))
		_ = s.sender.json(statusMessage{Type: msgStatus, State: stateTerminated, Reason: reason})
		s.cancel()
		return false
	}
	return true
}

// sanitizeDialError trims a dial error to a short, operator-safe phrase so the
// browser never sees an internal address or stack-y wrapping.
func sanitizeDialError(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 && i+2 < len(msg) {
		return msg[i+2:]
	}
	return msg
}
