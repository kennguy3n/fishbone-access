package gateway

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// maxRESPBulkLen caps a single RESP bulk-string length the proxy will buffer
// while parsing an operator command, so a malicious client cannot announce a
// multi-gigabyte argument and exhaust gateway memory. Real Redis commands the
// gateway needs to inspect (the command verb and its key arguments) are tiny;
// genuinely large payloads (e.g. a big SET value) still flow because the proxy
// streams the recorded copy rather than holding the whole request — but a
// single argument above this bound is treated as a protocol error.
const maxRESPBulkLen = 64 << 20

// maxRESPArrayLen caps the element count of a single multibulk command for the
// same reason: a command with an absurd argument count is a protocol abuse, not
// a real Redis call.
const maxRESPArrayLen = 1 << 20

// maxRESPLineLen bounds a single status/error reply line the proxy reads off
// the socket (e.g. the upstream AUTH reply). A real RESP simple-string reply is
// a few bytes; this cap stops a misbehaving upstream from streaming an
// unbounded line with no terminator.
const maxRESPLineLen = 64 << 10

// maxPreAuthCommands bounds how many commands the proxy will service before the
// operator presents a connect token via AUTH. Redis clients send at most a
// handful of pre-auth commands (PING/HELLO) before AUTH; a client that never
// authenticates is dropped rather than allowed to loop forever.
const maxPreAuthCommands = 16

// RedisProxy is the gateway.ConnHandler for the Redis listener (:6379). The
// operator points any Redis client at the gateway and presents the one-shot
// connect token as the AUTH password (redis-cli -a <token>). The proxy redeems
// it, dials the upstream server, authenticates with the JIT-injected vault
// credential, then frame-proxies the RESP stream: every command is recorded and
// gated against the 1C policy engine before it reaches the upstream, so an
// admin can deny destructive verbs (FLUSHALL, FLUSHDB, DEL, CONFIG SET, …) with
// a policy. Both directions are recorded for replay and appended to the
// workspace audit hash chain via the session manager.
type RedisProxy struct {
	broker      *pam.Broker
	sessions    *pam.SessionManager
	hub         *SessionHub
	store       ReplayStore
	dialTimeout time.Duration
	recMaxBytes int
}

// RedisProxyConfig configures a RedisProxy.
type RedisProxyConfig struct {
	Broker      *pam.Broker
	Sessions    *pam.SessionManager
	Hub         *SessionHub
	Store       ReplayStore
	DialTimeout time.Duration
	RecMaxBytes int
}

// NewRedisProxy builds a RedisProxy. broker and sessions are required.
func NewRedisProxy(cfg RedisProxyConfig) (*RedisProxy, error) {
	if cfg.Broker == nil || cfg.Sessions == nil {
		return nil, errors.New("gateway: RedisProxy requires broker and session manager")
	}
	dt := cfg.DialTimeout
	if dt <= 0 {
		dt = 15 * time.Second
	}
	return &RedisProxy{
		broker:      cfg.Broker,
		sessions:    cfg.Sessions,
		hub:         cfg.Hub,
		store:       cfg.Store,
		dialTimeout: dt,
		recMaxBytes: cfg.RecMaxBytes,
	}, nil
}

// Handle implements gateway.ConnHandler.
func (p *RedisProxy) Handle(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	clientAddr := conn.RemoteAddr().String()

	// Bound operator authentication with a read deadline so a client that opens
	// the TCP connection but never sends an AUTH cannot pin the serving
	// goroutine open indefinitely (slowloris-style resource exhaustion). The
	// deadline is cleared once authentication completes so steady-state proxying
	// is not bounded by the dial timeout. Mirrors the RDP/VNC/MongoDB/MSSQL
	// handlers, which all deadline their pre-auth read.
	_ = conn.SetReadDeadline(time.Now().Add(p.dialTimeout))
	br := bufio.NewReader(conn)
	token, err := p.authenticateOperator(br, conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		logger.Warnf(ctx, "redis-proxy: operator auth from %s failed: %v", clientAddr, err)
		return
	}

	leased, err := p.broker.RedeemConnectToken(ctx, token, clientAddr)
	if err != nil {
		writeRESPError(conn, "ERR connect token rejected")
		logger.Warnf(ctx, "redis-proxy: redeem from %s failed: %v", clientAddr, err)
		return
	}
	if leased.Target.Protocol != models.PAMProtocolRedis {
		writeRESPError(conn, "ERR token is not for a redis target")
		// RedeemConnectToken already consumed the token and opened the session;
		// reconcile it closed so it does not orphan active with no proxy.
		reconcileOrphanSession(ctx, p.sessions, leased.Session, "redis-proxy")
		return
	}
	session := leased.Session
	logger.Infof(ctx, "redis-proxy: session %s opened for %s → %s", session.ID, session.Subject, leased.Target.Address)

	rec := NewIORecorder(session.ID.String(), p.recMaxBytes)
	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if p.hub != nil {
		defer p.hub.Register(session.ID, session.WorkspaceID, session.Subject, rec, cancel)()
	}
	defer func() {
		flushCtx, fcancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer fcancel()
		if err := rec.Flush(flushCtx, p.store); err != nil {
			logger.Warnf(ctx, "redis-proxy: flush replay %s: %v", session.ID, err)
		}
		if err := p.sessions.CloseSession(flushCtx, session.WorkspaceID, session.ID); err != nil {
			logger.Warnf(ctx, "redis-proxy: close session %s: %v", session.ID, err)
		}
	}()

	upstream, err := p.dialUpstream(sessCtx, leased)
	if err != nil {
		writeRESPError(conn, "ERR upstream connection failed")
		rec.Annotate(fmt.Sprintf("[upstream connect failed: %v]", err))
		logger.Warnf(ctx, "redis-proxy: upstream %s: %v", leased.Target.Address, err)
		return
	}
	defer func() { _ = upstream.Close() }()

	// The operator's AUTH succeeded against the gateway; acknowledge it so the
	// client proceeds to its real commands.
	if _, err := conn.Write([]byte("+OK\r\n")); err != nil {
		return
	}

	p.splice(sessCtx, conn, br, upstream, session, rec, cancel)
}

// authenticateOperator reads operator commands until it sees an AUTH carrying
// the one-shot connect token, returning that token. Commands sent before AUTH
// are answered like a password-protected Redis would (PING is allowed; anything
// else gets NOAUTH) so a real client's handshake (e.g. an initial PING) does
// not wedge the proxy. The token is the AUTH password: redis-cli sends either
// `AUTH <token>` or `AUTH <user> <token>`.
func (p *RedisProxy) authenticateOperator(br *bufio.Reader, w io.Writer) (string, error) {
	for i := 0; i < maxPreAuthCommands; i++ {
		args, _, err := readRESPCommand(br)
		if err != nil {
			return "", fmt.Errorf("read pre-auth command: %w", err)
		}
		if len(args) == 0 {
			continue
		}
		switch strings.ToUpper(args[0]) {
		case "AUTH":
			// AUTH password | AUTH username password. The token is the final
			// argument in both forms.
			if len(args) < 2 {
				writeRESPError(w, "ERR wrong number of arguments for 'auth' command")
				continue
			}
			return args[len(args)-1], nil
		case "PING":
			if _, err := w.Write([]byte("+PONG\r\n")); err != nil {
				return "", err
			}
		case "QUIT":
			_, _ = w.Write([]byte("+OK\r\n"))
			return "", errors.New("operator quit before authenticating")
		default:
			// Mirror Redis behaviour when a password is required: refuse any
			// command until the client authenticates.
			writeRESPError(w, "NOAUTH Authentication required.")
		}
	}
	return "", errors.New("operator did not authenticate within command limit")
}

// dialUpstream opens a TCP connection to the upstream Redis server and, when the
// vault credential carries a password, authenticates with AUTH (RESP2). A
// username (Redis 6+ ACL) is included when present.
func (p *RedisProxy) dialUpstream(ctx context.Context, leased *pam.LeasedSession) (net.Conn, error) {
	d := net.Dialer{Timeout: p.dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", leased.Target.Address)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", leased.Target.Address, err)
	}
	password := leased.Secret.Password
	if password == "" {
		// An upstream with no password set needs no AUTH; the connection is
		// already usable.
		return conn, nil
	}
	user := credUser(leased)
	var authCmd []byte
	if user != "" {
		authCmd = encodeRESPCommand("AUTH", user, password)
	} else {
		authCmd = encodeRESPCommand("AUTH", password)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(p.dialTimeout)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set upstream auth deadline: %w", err)
	}
	if _, err := conn.Write(authCmd); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("send upstream AUTH: %w", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(p.dialTimeout)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set upstream auth read deadline: %w", err)
	}
	// Read the AUTH reply directly off the socket rather than via a throwaway
	// bufio.Reader: a buffered reader can pull bytes past the reply line into
	// its buffer, and those bytes would be silently dropped when steady-state
	// proxying takes over the raw connection below.
	line, err := readUpstreamLine(conn, maxRESPLineLen)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read upstream AUTH reply: %w", err)
	}
	if len(line) == 0 || line[0] != '+' {
		_ = conn.Close()
		return nil, fmt.Errorf("gateway: upstream rejected AUTH: %s", strings.TrimSpace(line))
	}
	// Clear the deadlines so steady-state proxying is not bounded by the dial
	// timeout.
	_ = conn.SetReadDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Time{})
	return conn, nil
}

// splice runs the steady-state RESP frame proxy. Operator commands are parsed
// one at a time so each can be gated; upstream replies are copied raw and
// recorded as output.
func (p *RedisProxy) splice(ctx context.Context, operator net.Conn, operatorBuf *bufio.Reader, upstream net.Conn, session *models.PAMSession, rec *IORecorder, cancel context.CancelFunc) {
	var wg sync.WaitGroup

	// Both relay directions write to the operator connection: the command loop
	// injects deny replies, the copy loop streams upstream replies. Funnel both
	// through one lockedWriter so a deny frame and an upstream reply frame can
	// never interleave their bytes on the socket.
	operatorOut := newLockedWriter(operator)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		p.forwardOperatorCommands(ctx, operatorOut, operatorBuf, upstream, session, rec)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		_, _ = io.Copy(operatorOut, rec.TeeReader(DirOutput, upstream))
	}()

	go func() {
		<-ctx.Done()
		_ = operator.Close()
		_ = upstream.Close()
	}()

	wg.Wait()
}

// forwardOperatorCommands reads operator commands, gates each against policy,
// and forwards the allowed ones upstream. A denied command is answered with a
// RESP error and NOT forwarded; because Redis is strictly request/response the
// stream stays in sync, so the session continues rather than being severed (the
// operator simply cannot run that command).
func (p *RedisProxy) forwardOperatorCommands(ctx context.Context, operator io.Writer, operatorBuf *bufio.Reader, upstream net.Conn, session *models.PAMSession, rec *IORecorder) {
	for {
		args, raw, err := readRESPCommand(operatorBuf)
		if err != nil {
			return
		}
		if len(args) == 0 {
			// Empty inline line: forward verbatim so we never desync the stream.
			if _, err := upstream.Write(raw); err != nil {
				return
			}
			continue
		}
		command := redisCommandString(args)
		rec.Record(DirInput, []byte(command+"\n"))

		// QUIT is a control verb; record and forward it, then let the upstream
		// close the connection.
		decision, derr := p.sessions.LogCommand(ctx, session, command)
		if derr != nil || !decision.Allowed() {
			reason := decision.Reason
			if reason == "" {
				reason = "denied by command policy"
			}
			rec.Annotate(fmt.Sprintf("[command denied: %s]", reason))
			writeRESPError(operator, "ERR pam-gateway: "+reason)
			continue
		}
		if _, err := upstream.Write(raw); err != nil {
			return
		}
	}
}

// readUpstreamLine reads a single line terminated by '\n' directly from conn,
// one byte at a time, returning the line including the terminator. Reading
// without a bufio.Reader guarantees no bytes past the line are consumed from
// the socket, so a subsequent raw-proxy copy starts exactly after this reply.
// The returned line is capped at max bytes to bound memory against an upstream
// that never sends a terminator.
func readUpstreamLine(conn net.Conn, max int) (string, error) {
	buf := make([]byte, 0, 64)
	one := make([]byte, 1)
	for {
		n, err := conn.Read(one)
		if n > 0 {
			buf = append(buf, one[0])
			if one[0] == '\n' {
				return string(buf), nil
			}
			if len(buf) >= max {
				return string(buf), errors.New("gateway: upstream reply line exceeds limit")
			}
		}
		if err != nil {
			return string(buf), err
		}
	}
}

// --- RESP wire helpers ---

// readRESPCommand reads one client command from r, returning its arguments as
// strings and the exact raw bytes that made it up (so the proxy can forward an
// allowed command byte-for-byte without re-encoding). It supports both the
// RESP multibulk array form that all modern clients use and the legacy inline
// form. Bulk lengths and array counts are bounded to protect gateway memory.
func readRESPCommand(r *bufio.Reader) (args []string, raw []byte, err error) {
	prefix, err := r.ReadByte()
	if err != nil {
		return nil, nil, err
	}
	if prefix != '*' {
		// Inline command: the whole line is the command, space-separated.
		if err := r.UnreadByte(); err != nil {
			return nil, nil, err
		}
		line, err := r.ReadBytes('\n')
		if err != nil {
			return nil, nil, err
		}
		fields := strings.Fields(string(line))
		return fields, line, nil
	}

	var buf []byte
	buf = append(buf, prefix)
	countLine, err := r.ReadBytes('\n')
	if err != nil {
		return nil, nil, err
	}
	buf = append(buf, countLine...)
	n, err := strconv.Atoi(strings.TrimRight(string(countLine), "\r\n"))
	if err != nil {
		return nil, nil, fmt.Errorf("gateway: malformed RESP array count: %w", err)
	}
	if n < 0 {
		// Null array: a valid, empty command.
		return nil, buf, nil
	}
	if n > maxRESPArrayLen {
		return nil, nil, fmt.Errorf("gateway: RESP array too large (%d elements)", n)
	}
	args = make([]string, 0, n)
	for i := 0; i < n; i++ {
		typ, err := r.ReadByte()
		if err != nil {
			return nil, nil, err
		}
		buf = append(buf, typ)
		if typ != '$' {
			return nil, nil, fmt.Errorf("gateway: expected RESP bulk string, got %q", typ)
		}
		lenLine, err := r.ReadBytes('\n')
		if err != nil {
			return nil, nil, err
		}
		buf = append(buf, lenLine...)
		blen, err := strconv.Atoi(strings.TrimRight(string(lenLine), "\r\n"))
		if err != nil {
			return nil, nil, fmt.Errorf("gateway: malformed RESP bulk length: %w", err)
		}
		if blen < 0 {
			// Null bulk string element.
			args = append(args, "")
			continue
		}
		if blen > maxRESPBulkLen {
			return nil, nil, fmt.Errorf("gateway: RESP bulk string too large (%d bytes)", blen)
		}
		// Read the payload plus the trailing CRLF.
		payload := make([]byte, blen+2)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, nil, err
		}
		buf = append(buf, payload...)
		args = append(args, string(payload[:blen]))
	}
	return args, buf, nil
}

// encodeRESPCommand encodes a command as a RESP multibulk array, the form every
// modern Redis server accepts.
func encodeRESPCommand(parts ...string) []byte {
	var b []byte
	b = append(b, '*')
	b = append(b, []byte(strconv.Itoa(len(parts)))...)
	b = append(b, '\r', '\n')
	for _, p := range parts {
		b = append(b, '$')
		b = append(b, []byte(strconv.Itoa(len(p)))...)
		b = append(b, '\r', '\n')
		b = append(b, []byte(p)...)
		b = append(b, '\r', '\n')
	}
	return b
}

// redisCommandString renders a parsed command for policy evaluation and
// recording. The verb is upper-cased (Redis verbs are case-insensitive) so a
// policy pattern like "cmd:FLUSHALL" matches regardless of how the operator
// typed it; arguments are preserved so a pattern can target a specific key
// (e.g. "cmd:CONFIG SET *").
func redisCommandString(args []string) string {
	if len(args) == 0 {
		return ""
	}
	parts := make([]string, len(args))
	parts[0] = strings.ToUpper(args[0])
	// Normalise the subcommand of container commands (CONFIG, CLIENT, …) too so
	// "CONFIG set" and "CONFIG SET" gate identically.
	if len(args) > 1 && isRedisContainerCommand(parts[0]) {
		parts[1] = strings.ToUpper(args[1])
	} else if len(args) > 1 {
		parts[1] = args[1]
	}
	for i := 2; i < len(args); i++ {
		parts[i] = args[i]
	}
	return strings.Join(parts, " ")
}

// isRedisContainerCommand reports whether verb is a Redis command whose first
// argument is itself a subcommand (so the proxy upper-cases it for stable
// gating).
func isRedisContainerCommand(verb string) bool {
	switch verb {
	case "CONFIG", "CLIENT", "CLUSTER", "COMMAND", "ACL", "XGROUP", "XINFO", "OBJECT", "MEMORY", "LATENCY", "SCRIPT", "FUNCTION", "PUBSUB", "SLOWLOG":
		return true
	default:
		return false
	}
}

// writeRESPError writes a RESP error reply (-ERR …) to the operator.
func writeRESPError(w io.Writer, msg string) {
	_, _ = fmt.Fprintf(w, "-%s\r\n", msg)
}
