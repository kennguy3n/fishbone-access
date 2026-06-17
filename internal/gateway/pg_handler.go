package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// PostgresProxy is the gateway.ConnHandler for the PostgreSQL listener (:5432).
// It terminates the operator's wire-protocol handshake at the gateway: the
// operator presents a one-shot connect token in the password field, which the
// proxy redeems. The proxy then connects to the upstream cluster with the
// JIT-injected vault credential (pgconn handles SCRAM-SHA-256/MD5/TLS), hijacks
// the authenticated connection, and splices the two protocol streams. Every
// Simple-Query and extended-protocol Parse is gated against the policy
// engine and appended to the workspace audit hash chain before it reaches the
// cluster.
type PostgresProxy struct {
	broker      *pam.Broker
	sessions    *pam.SessionManager
	hub         *SessionHub
	store       ReplayStore
	tlsConfig   *tls.Config
	dialTimeout time.Duration
	dialer      TargetDialer
	recMaxBytes int
	// kerberosService is the default Kerberos service name used to build the
	// upstream SPN (service/host) for a Kerberos target that does not override
	// it. Empty lets pgconn use its own "postgres" default.
	kerberosService string
}

// PostgresProxyConfig configures a PostgresProxy.
type PostgresProxyConfig struct {
	Broker      *pam.Broker
	Sessions    *pam.SessionManager
	Hub         *SessionHub
	Store       ReplayStore
	TLSConfig   *tls.Config
	DialTimeout time.Duration
	// Dialer establishes the upstream transport. Nil dials directly (the
	// default); a broker dialer routes via-agent targets through the tunnel.
	Dialer      TargetDialer
	RecMaxBytes int
	// KerberosService is the default Kerberos service name used when a target
	// opts into GSSAPI upstream auth without naming one. Empty defers to
	// pgconn's "postgres" default.
	KerberosService string
}

// NewPostgresProxy builds a PostgresProxy.
func NewPostgresProxy(cfg PostgresProxyConfig) (*PostgresProxy, error) {
	if cfg.Broker == nil || cfg.Sessions == nil {
		return nil, errors.New("gateway: PostgresProxy requires broker and session manager")
	}
	dt := cfg.DialTimeout
	if dt <= 0 {
		dt = 15 * time.Second
	}
	// Default to an ephemeral self-signed cert so the operator↔gateway hop is
	// encrypted out of the box (sslmode=require). Operators that need a verified
	// chain pass a real keypair via cfg.TLSConfig. A client that disables SSL
	// still works: it sends no SSLRequest and we read its StartupMessage directly.
	tlsCfg := cfg.TLSConfig
	if tlsCfg == nil {
		cert, err := ephemeralTLSCert()
		if err != nil {
			return nil, fmt.Errorf("gateway: postgres ephemeral cert: %w", err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	return &PostgresProxy{
		broker:          cfg.Broker,
		sessions:        cfg.Sessions,
		hub:             cfg.Hub,
		store:           cfg.Store,
		tlsConfig:       tlsCfg,
		dialTimeout:     dt,
		dialer:          resolveDialer(cfg.Dialer, dt),
		recMaxBytes:     cfg.RecMaxBytes,
		kerberosService: cfg.KerberosService,
	}, nil
}

// Handle implements gateway.ConnHandler.
func (p *PostgresProxy) Handle(ctx context.Context, conn net.Conn) {
	// Close whatever conn points to at return — after a TLS upgrade this is the
	// tls.Conn, so its Close sends close_notify and shuts the underlying socket.
	defer func() { _ = conn.Close() }()
	clientAddr := conn.RemoteAddr().String()
	backend := pgproto3.NewBackend(conn, conn)

	// readStartup may upgrade the connection to TLS, returning the encrypted
	// conn and a backend bound to it; everything after this point (auth, splice)
	// must use the returned conn/backend, not the originals.
	startup, conn, backend, err := p.readStartup(ctx, backend, conn)
	if err != nil {
		logger.Warnf(ctx, "pg-proxy: startup from %s failed: %v", clientAddr, err)
		return
	}
	if startup == nil {
		// Client only probed SSL/GSS and disconnected.
		return
	}

	token, err := p.authenticate(backend)
	if err != nil {
		writeFatal(backend, "28P01", "connect token rejected")
		logger.Warnf(ctx, "pg-proxy: auth from %s failed: %v", clientAddr, err)
		return
	}
	leased, err := p.broker.RedeemConnectToken(ctx, token, clientAddr)
	if err != nil {
		writeFatal(backend, "28P01", "connect token rejected")
		logger.Warnf(ctx, "pg-proxy: redeem from %s failed: %v", clientAddr, err)
		return
	}
	if leased.Target.Protocol != models.PAMProtocolPostgres {
		writeFatal(backend, "08P01", "token is not for a postgres target")
		// RedeemConnectToken already consumed the token and opened the session;
		// reconcile it closed so it does not orphan active with no proxy.
		reconcileOrphanSession(ctx, p.sessions, leased.Session, "pg-proxy")
		return
	}
	session := leased.Session
	logger.Infof(ctx, "pg-proxy: session %s opened for %s → %s", session.ID, session.Subject, leased.Target.Address)

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
			logger.Warnf(ctx, "pg-proxy: flush replay %s: %v", session.ID, err)
		}
		if recording := rec.Recording(); recording.Stored {
			if err := p.sessions.RecordRecording(flushCtx, session, pam.RecordingRef{
				Key: recording.Key, SHA256: recording.SHA256, Bytes: recording.Bytes, Truncated: recording.Truncated,
			}); err != nil {
				logger.Warnf(ctx, "pg-proxy: record recording evidence %s: %v", session.ID, err)
			}
		}
		if err := p.sessions.CloseSession(flushCtx, session.WorkspaceID, session.ID); err != nil {
			logger.Warnf(ctx, "pg-proxy: close session %s: %v", session.ID, err)
		}
	}()

	hj, err := p.dialUpstream(sessCtx, leased, startupDatabase(startup))
	if err != nil {
		writeFatal(backend, "08006", "upstream connection failed")
		rec.Annotate(fmt.Sprintf("[upstream connect failed: %v]", err))
		logger.Warnf(ctx, "pg-proxy: upstream %s: %v", leased.Target.Address, err)
		return
	}
	defer hj.Conn.Close()

	if err := p.completeOperatorAuth(backend, hj); err != nil {
		logger.Warnf(ctx, "pg-proxy: complete operator auth: %v", err)
		return
	}

	p.splice(sessCtx, conn, backend, hj, session, rec, cancel)
}

// readStartup reads the operator's startup phase. On an SSLRequest it performs
// a real TLS upgrade (responding 'S', handshaking with the gateway cert) and
// re-creates the backend over the encrypted stream, so the connect token and
// all session SQL are protected on the operator↔gateway hop. GSSAPI encryption
// is not implemented, so a GSSEncRequest is refused ('N') and the client falls
// back to SSL or plaintext. It returns the StartupMessage plus the (possibly
// upgraded) conn and backend the caller must use from here on, or a nil
// StartupMessage when the client only probed and hung up.
func (p *PostgresProxy) readStartup(ctx context.Context, backend *pgproto3.Backend, conn net.Conn) (*pgproto3.StartupMessage, net.Conn, *pgproto3.Backend, error) {
	for {
		msg, err := backend.ReceiveStartupMessage()
		if err != nil {
			return nil, conn, backend, fmt.Errorf("receive startup: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.StartupMessage:
			return m, conn, backend, nil
		case *pgproto3.SSLRequest:
			if p.tlsConfig == nil {
				// No server cert configured: refuse, client retries in plaintext.
				if _, err := conn.Write([]byte("N")); err != nil {
					return nil, conn, backend, fmt.Errorf("refuse ssl: %w", err)
				}
				continue
			}
			// Accept TLS: ack with 'S', upgrade, and rebind the backend to the
			// encrypted conn. Per the protocol the client re-sends its startup
			// packet after the handshake, so the loop continues.
			if _, err := conn.Write([]byte("S")); err != nil {
				return nil, conn, backend, fmt.Errorf("accept ssl: %w", err)
			}
			tlsConn := tls.Server(conn, p.tlsConfig)
			hsCtx, hsCancel := context.WithTimeout(ctx, p.dialTimeout)
			err := tlsConn.HandshakeContext(hsCtx)
			hsCancel()
			if err != nil {
				return nil, conn, backend, fmt.Errorf("tls handshake: %w", err)
			}
			conn = tlsConn
			backend = pgproto3.NewBackend(conn, conn)
		case *pgproto3.GSSEncRequest:
			// Decline operator-side GSSAPI *encryption* so the client falls back
			// to TLS (which the gateway already provides on this hop and is the
			// lossless equivalent; pgbouncer behaves the same). This is distinct
			// from upstream Kerberos *authentication* to the target cluster, which
			// the proxy does support — see dialUpstream/applyKerberosUpstreamAuth.
			if _, err := conn.Write([]byte("N")); err != nil {
				return nil, conn, backend, fmt.Errorf("refuse gss: %w", err)
			}
		case *pgproto3.CancelRequest:
			// A cancel request is a one-shot out-of-band connection; nothing to
			// proxy here.
			return nil, conn, backend, nil
		default:
			return nil, conn, backend, fmt.Errorf("unexpected startup message %T", msg)
		}
	}
}

// authenticate requests a cleartext password (the operator's connect token) and
// returns it.
func (p *PostgresProxy) authenticate(backend *pgproto3.Backend) (string, error) {
	backend.Send(&pgproto3.AuthenticationCleartextPassword{})
	if err := backend.Flush(); err != nil {
		return "", fmt.Errorf("send auth request: %w", err)
	}
	if err := backend.SetAuthType(pgproto3.AuthTypeCleartextPassword); err != nil {
		return "", fmt.Errorf("set auth type: %w", err)
	}
	msg, err := backend.Receive()
	if err != nil {
		return "", fmt.Errorf("receive password: %w", err)
	}
	pw, ok := msg.(*pgproto3.PasswordMessage)
	if !ok {
		return "", fmt.Errorf("expected password message, got %T", msg)
	}
	return pw.Password, nil
}

// dialUpstream connects to the target with the injected credential and hijacks
// the authenticated connection for splicing.
func (p *PostgresProxy) dialUpstream(ctx context.Context, leased *pam.LeasedSession, database string) (*pgconn.HijackedConn, error) {
	host, port, err := net.SplitHostPort(leased.Target.Address)
	if err != nil {
		return nil, fmt.Errorf("parse target address: %w", err)
	}
	user := leased.Target.Username
	if user == "" {
		user = leased.Secret.Username
	}
	targetCfg := decodeTargetConfig(leased.Target.Config)
	if database == "" {
		database = targetCfg["database"]
	}
	if database == "" {
		database = user
	}

	cfg, err := pgconn.ParseConfig("")
	if err != nil {
		return nil, fmt.Errorf("base config: %w", err)
	}
	cfg.Host = host
	cfg.Port = parsePort(port)
	cfg.User = user
	cfg.Password = leased.Secret.Password
	cfg.Database = database
	cfg.ConnectTimeout = p.dialTimeout
	// Route the upstream transport through the dialer seam so a via-agent target
	// is reached over the agent tunnel; pgconn then negotiates the protocol over
	// the returned net.Conn exactly as over a direct dial.
	cfg.DialFunc = func(dialCtx context.Context, _, _ string) (net.Conn, error) {
		return p.dialer.DialTarget(dialCtx, leased.Target)
	}
	// Upstream GSSAPI/Kerberos: when the target opts in (auth_mode=kerberos|gssapi
	// or an explicit krb_spn/krb_service), authenticate with the gateway's service
	// ticket via the registered GSS provider instead of a vault password. pgconn
	// performs the ticket exchange automatically when the upstream answers the
	// startup packet with AuthenticationGSS.
	if applyKerberosUpstreamAuth(cfg, targetCfg, p.kerberosService) {
		logger.Infof(ctx, "pg-proxy: upstream %s using kerberos auth (spn=%q srv=%q)", leased.Target.Address, cfg.KerberosSpn, cfg.KerberosSrvName)
	}
	// pgconn negotiates TLS per the server's capabilities; leave TLSConfig at
	// the parsed default (sslmode=prefer) so an encrypted upstream is used when
	// available without failing a plaintext-only target.

	dialCtx, dcancel := context.WithTimeout(ctx, p.dialTimeout)
	defer dcancel()
	pgConn, err := pgconn.ConnectConfig(dialCtx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect upstream: %w", err)
	}
	if err := pgConn.SyncConn(dialCtx); err != nil {
		_ = pgConn.Close(dialCtx)
		return nil, fmt.Errorf("sync upstream: %w", err)
	}
	hj, err := pgConn.Hijack()
	if err != nil {
		_ = pgConn.Close(dialCtx)
		return nil, fmt.Errorf("hijack upstream: %w", err)
	}
	return hj, nil
}

// completeOperatorAuth tells the operator the login succeeded, replaying the
// upstream's reported parameters and backend key so the operator's client sees
// a normal post-authentication handshake.
func (p *PostgresProxy) completeOperatorAuth(backend *pgproto3.Backend, hj *pgconn.HijackedConn) error {
	backend.Send(&pgproto3.AuthenticationOk{})
	for name, value := range hj.ParameterStatuses {
		backend.Send(&pgproto3.ParameterStatus{Name: name, Value: value})
	}
	backend.Send(&pgproto3.BackendKeyData{ProcessID: hj.PID, SecretKey: hj.SecretKey})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := backend.Flush(); err != nil {
		return fmt.Errorf("flush operator auth-ok: %w", err)
	}
	return nil
}

// pgSpliceState carries the per-connection state shared between the two
// bridging goroutines. txStatus mirrors the upstream's last ReadyForQuery
// transaction indicator ('I' idle, 'T' in-transaction, 'E' failed) so that a
// synthesised ReadyForQuery on a policy deny reports the operator's real
// transaction state instead of a hardcoded guess.
type pgSpliceState struct {
	mu       sync.Mutex
	txStatus byte
}

func (s *pgSpliceState) setTxStatus(b byte) {
	s.mu.Lock()
	s.txStatus = b
	s.mu.Unlock()
}

func (s *pgSpliceState) currentTxStatus() byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.txStatus
}

// splice runs the two protocol-bridging loops until either side closes. On
// context cancellation (e.g. admin takeover termination, or one loop exiting)
// both the upstream and the operator connections are closed so that a goroutine
// blocked in Receive on either side unblocks and the handler returns.
func (p *PostgresProxy) splice(ctx context.Context, conn net.Conn, backend *pgproto3.Backend, hj *pgconn.HijackedConn, session *models.PAMSession, rec *IORecorder, cancel context.CancelFunc) {
	frontend := hj.Frontend
	state := &pgSpliceState{txStatus: 'I'}
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		p.forwardOperatorToUpstream(ctx, backend, frontend, session, rec, state)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		forwardUpstreamToOperator(backend, frontend, rec, state)
	}()

	go func() {
		<-ctx.Done()
		_ = hj.Conn.Close()
		_ = conn.Close()
	}()

	wg.Wait()
}

// forwardOperatorToUpstream relays frontend messages, gating queries.
func (p *PostgresProxy) forwardOperatorToUpstream(ctx context.Context, backend *pgproto3.Backend, frontend *pgproto3.Frontend, session *models.PAMSession, rec *IORecorder, state *pgSpliceState) {
	for {
		// Honour the live soft-pause gate before reading the next operator
		// message: while an admin has frozen the session no further frontend
		// query is pulled or forwarded to the upstream database.
		rec.WaitWhilePaused()
		msg, err := backend.Receive()
		if err != nil {
			return
		}
		switch m := msg.(type) {
		case *pgproto3.Query:
			// Simple query: the whole cycle is one message, so a deny is a
			// self-contained ErrorResponse + ReadyForQuery.
			if allowed, reason := p.evaluate(ctx, session, rec, m.String); !allowed {
				p.denySimple(backend, rec, reason, state.currentTxStatus())
				continue
			}
		case *pgproto3.Parse:
			// Extended query: Parse/Bind/Describe/Execute/Sync are pipelined.
			// PostgreSQL's own error handling sends ErrorResponse, then ignores
			// every following message until the Sync synchronisation point, then
			// sends ReadyForQuery. We mirror that exactly; otherwise the trailing
			// Bind/Describe/Execute would fall through and be forwarded to an
			// upstream that never received the prepared statement, desynchronising
			// the operator's libpq protocol state machine.
			if allowed, reason := p.evaluate(ctx, session, rec, m.Query); !allowed {
				if !p.denyExtended(backend, rec, reason, state) {
					return
				}
				continue
			}
		case *pgproto3.Terminate:
			frontend.Send(m)
			_ = frontend.Flush()
			return
		}
		frontend.Send(msg)
		if err := frontend.Flush(); err != nil {
			return
		}
	}
}

// evaluate records one SQL statement and runs it through the command policy.
// It returns whether the statement is allowed and, when denied, the reason.
func (p *PostgresProxy) evaluate(ctx context.Context, session *models.PAMSession, rec *IORecorder, sql string) (bool, string) {
	rec.Record(DirInput, []byte(sql+"\n"))
	decision, err := p.sessions.LogCommand(ctx, session, sql)
	if err != nil || !decision.Allowed() {
		reason := decision.Reason
		if reason == "" {
			reason = "denied by command policy"
		}
		return false, reason
	}
	return true, ""
}

// denySimple answers a denied simple Query with ErrorResponse + ReadyForQuery,
// reporting the operator's real transaction state so libpq stays in sync.
func (p *PostgresProxy) denySimple(backend *pgproto3.Backend, rec *IORecorder, reason string, txStatus byte) {
	rec.Annotate(fmt.Sprintf("[query denied: %s]", reason))
	backend.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42501", Message: "pam-gateway: " + reason})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: txStatus})
	_ = backend.Flush()
}

// denyExtended answers a denied Parse the way PostgreSQL does: send
// ErrorResponse immediately, discard the rest of the pipelined extended-query
// messages up to and including Sync, then send a single ReadyForQuery. It
// returns false if the operator connection failed or was terminated mid-drain.
func (p *PostgresProxy) denyExtended(backend *pgproto3.Backend, rec *IORecorder, reason string, state *pgSpliceState) bool {
	rec.Annotate(fmt.Sprintf("[query denied: %s]", reason))
	backend.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42501", Message: "pam-gateway: " + reason})
	if err := backend.Flush(); err != nil {
		return false
	}
	if !drainUntilSync(backend) {
		return false
	}
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: state.currentTxStatus()})
	return backend.Flush() == nil
}

// drainUntilSync reads and discards frontend messages until a Sync is seen,
// matching PostgreSQL's "skip until synchronisation point" error recovery.
// It returns false if the stream ended or the client terminated before Sync.
func drainUntilSync(backend *pgproto3.Backend) bool {
	for {
		msg, err := backend.Receive()
		if err != nil {
			return false
		}
		switch msg.(type) {
		case *pgproto3.Sync:
			return true
		case *pgproto3.Terminate:
			return false
		}
	}
}

// forwardUpstreamToOperator relays backend messages to the operator, recording
// command tags and errors into the session transcript and tracking the
// upstream transaction status from each ReadyForQuery.
func forwardUpstreamToOperator(backend *pgproto3.Backend, frontend *pgproto3.Frontend, rec *IORecorder, state *pgSpliceState) {
	for {
		msg, err := frontend.Receive()
		if err != nil {
			return
		}
		switch m := msg.(type) {
		case *pgproto3.CommandComplete:
			rec.Record(DirOutput, append([]byte("-- "), append(m.CommandTag, '\n')...))
		case *pgproto3.ErrorResponse:
			rec.Record(DirOutput, []byte(fmt.Sprintf("-- ERROR %s: %s\n", m.Code, m.Message)))
		case *pgproto3.ReadyForQuery:
			state.setTxStatus(m.TxStatus)
		}
		backend.Send(msg)
		if err := backend.Flush(); err != nil {
			return
		}
	}
}

// writeFatal sends a fatal ErrorResponse to the operator before disconnecting.
func writeFatal(backend *pgproto3.Backend, code, message string) {
	backend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: code, Message: "pam-gateway: " + message})
	_ = backend.Flush()
}

// startupDatabase extracts the requested database from a startup message.
func startupDatabase(startup *pgproto3.StartupMessage) string {
	if startup == nil {
		return ""
	}
	return strings.TrimSpace(startup.Parameters["database"])
}

// parsePort converts a port string to uint16, defaulting to 5432 on error.
func parsePort(s string) uint16 {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n <= 0 || n > 65535 {
		return 5432
	}
	return uint16(n)
}
