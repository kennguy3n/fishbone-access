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

	sessCtx, cancel := context.WithCancel(ctx)
	rec := NewIORecorder(sessCtx, session.ID.String(), p.recMaxBytes)
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

// splice runs the steady-state RESP frame proxy as a single, strictly
// sequential request/reply loop: it reads one operator command, gates it, and
// either forwards it upstream and relays exactly one upstream reply, or answers
// it locally with a synthetic error. Both directions are driven by one
// goroutine on purpose.
//
// Redis carries no per-message correlation id; a client (especially a pipelined
// one) pairs the Nth reply it reads with the Nth command it sent purely by
// position. An earlier design ran the upstream→operator copy in a separate
// goroutine from the deny-reply injector, so a denied command's synthetic error
// could be written to the operator before or after an unrelated upstream reply,
// shifting every subsequent reply by one and handing the operator the wrong
// answer for a command. Driving reads and writes from one goroutine makes the
// reply order match the command order exactly, which mirrors how a real Redis
// connection processes a pipeline. The trade-off is that upstream I/O no longer
// overlaps command parsing; for an audited admin proxy that is the correct
// exchange.
func (p *RedisProxy) splice(ctx context.Context, operator net.Conn, operatorBuf *bufio.Reader, upstream net.Conn, session *models.PAMSession, rec *IORecorder, cancel context.CancelFunc) {
	upstreamBuf := bufio.NewReader(upstream)

	go func() {
		<-ctx.Done()
		_ = operator.Close()
		_ = upstream.Close()
	}()

	defer cancel()
	p.pump(ctx, operator, operatorBuf, upstream, upstreamBuf, session, rec)
}

// pump is the sequential request/reply loop described on splice. A denied
// command is answered with a RESP error and NOT forwarded; its synthetic error
// is this command's reply, written in command order, so pipelined clients stay
// in lockstep and the session continues (the operator simply cannot run that
// command) rather than being severed.
func (p *RedisProxy) pump(ctx context.Context, operator io.Writer, operatorBuf *bufio.Reader, upstream net.Conn, upstreamBuf *bufio.Reader, session *models.PAMSession, rec *IORecorder) {
	for {
		// Honour the live soft-pause gate before reading the next operator
		// command: while an admin has frozen the session no further RESP
		// command is pulled or forwarded to the upstream server.
		rec.WaitWhilePaused()
		args, raw, err := readRESPCommand(operatorBuf)
		if err != nil {
			return
		}
		if len(args) == 0 {
			// Empty inline line (bare CRLF) or null array: Redis produces no
			// reply for it, so drop it without forwarding. Forwarding it and
			// then blocking on a reply that never comes would stall the loop.
			continue
		}
		command := redisCommandString(args)
		rec.Record(DirInput, []byte(command+"\n"))

		decision, derr := p.sessions.LogCommand(ctx, session, command)
		if derr != nil || !decision.Allowed() {
			reason := decision.Reason
			if reason == "" {
				reason = "denied by command policy"
			}
			rec.Annotate(fmt.Sprintf("[command denied: %s]", reason))
			// Not forwarded, so no upstream reply is consumed; the synthetic
			// error stands in for this command's reply at the right position.
			writeRESPError(operator, "ERR pam-gateway: "+reason)
			continue
		}
		if _, err := upstream.Write(raw); err != nil {
			return
		}
		if err := p.relayReply(operator, upstreamBuf, rec); err != nil {
			return
		}
	}
}

// relayReply reads exactly one complete RESP reply from the upstream, records
// it as output, and writes it verbatim to the operator. Reading one whole reply
// (recursing into aggregate types) is what keeps the request/reply loop aligned
// for the next command.
func (p *RedisProxy) relayReply(operator io.Writer, upstreamBuf *bufio.Reader, rec *IORecorder) error {
	reply, err := readRESPReply(upstreamBuf)
	if err != nil {
		return err
	}
	rec.Record(DirOutput, reply)
	if _, err := operator.Write(reply); err != nil {
		return err
	}
	return nil
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

// maxRESPReplyDepth bounds how deeply nested an upstream reply may be while the
// proxy relays it. Aggregate replies (arrays, maps, sets, pushes) can nest, and
// a hostile or buggy upstream announcing pathological nesting must not be able
// to drive the gateway into unbounded recursion.
const maxRESPReplyDepth = 64

// readRESPReply reads exactly one complete RESP reply from r and returns its
// raw bytes verbatim, so the proxy can relay it to the operator without
// re-encoding. It understands both RESP2 and RESP3 reply types and recurses
// into aggregate replies (arrays, sets, maps, pushes) so that "one reply" means
// one whole value — which is what keeps the sequential request/reply loop
// aligned with the next command. Definite-length forms only; the rarely used
// RESP3 streamed forms (e.g. "$?") are rejected as a protocol error rather than
// guessed at, which fails closed.
func readRESPReply(r *bufio.Reader) ([]byte, error) {
	return readRESPReplyDepth(r, 0)
}

func readRESPReplyDepth(r *bufio.Reader, depth int) ([]byte, error) {
	if depth > maxRESPReplyDepth {
		return nil, errors.New("gateway: RESP reply nesting too deep")
	}
	typ, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	switch typ {
	case '+', '-', ':', '_', '#', ',', '(':
		// Single-line replies: simple string, error, integer, null, boolean,
		// double and big number all terminate at the first CRLF.
		line, err := r.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		return append([]byte{typ}, line...), nil
	case '$', '=', '!':
		// Length-prefixed blobs: bulk string, verbatim string, blob error.
		return readRESPBlobReply(r, typ)
	case '*', '~', '>':
		// Aggregates whose header is an element count: array, set, push.
		return readRESPAggregateReply(r, typ, 1, depth)
	case '%':
		// Map: the header counts key/value pairs, so each unit is 2 elements.
		return readRESPAggregateReply(r, typ, 2, depth)
	default:
		return nil, fmt.Errorf("gateway: unknown RESP reply type %q", typ)
	}
}

// readRESPBlobReply reads a length-prefixed reply ($ bulk, = verbatim, ! blob
// error). A negative length is the null bulk ("$-1") and has no payload.
func readRESPBlobReply(r *bufio.Reader, typ byte) ([]byte, error) {
	lenLine, err := r.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	out := append([]byte{typ}, lenLine...)
	n, err := strconv.Atoi(strings.TrimRight(string(lenLine), "\r\n"))
	if err != nil {
		return nil, fmt.Errorf("gateway: malformed RESP bulk length: %w", err)
	}
	if n < 0 {
		return out, nil
	}
	if n > maxRESPBulkLen {
		return nil, fmt.Errorf("gateway: RESP bulk reply too large (%d bytes)", n)
	}
	payload := make([]byte, n+2) // payload + trailing CRLF
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return append(out, payload...), nil
}

// readRESPAggregateReply reads an aggregate reply (array, set, push or map),
// recursing into each element. perElem is 2 for maps (key+value per announced
// count) and 1 otherwise. A negative count is the null aggregate ("*-1").
func readRESPAggregateReply(r *bufio.Reader, typ byte, perElem, depth int) ([]byte, error) {
	countLine, err := r.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	out := append([]byte{typ}, countLine...)
	n, err := strconv.Atoi(strings.TrimRight(string(countLine), "\r\n"))
	if err != nil {
		return nil, fmt.Errorf("gateway: malformed RESP aggregate count: %w", err)
	}
	if n < 0 {
		return out, nil
	}
	if n > maxRESPArrayLen {
		return nil, fmt.Errorf("gateway: RESP aggregate too large (%d elements)", n)
	}
	for i := 0; i < n*perElem; i++ {
		elem, err := readRESPReplyDepth(r, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, elem...)
	}
	return out, nil
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
