package webaccess

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/gateway"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// kind is the protocol class a WebSocket route serves. The HTTP route fixes the
// kind (web SSH vs. web database console); the bridge then asserts the redeemed
// token's target protocol falls in that class, so a token minted for a DB
// target cannot be driven on the SSH terminal endpoint or vice-versa.
type kind int

const (
	kindSSH kind = iota
	kindDB
)

// handshakeTimeout bounds how long the bridge waits for the client's hello
// frame (the connect token) after the WebSocket upgrade, so a connection that
// opens but never authenticates is reaped quickly rather than holding a slot.
const handshakeTimeout = 20 * time.Second

// BridgeConfig wires the bridge to the shared PAM machinery and sets its
// resource envelope. Broker and Sessions are required; the rest degrade
// gracefully (no Hub ⇒ no live takeover of browser sessions; no Store ⇒
// recording is captured but not persisted; no CA ⇒ SSH uses credential
// injection only).
type BridgeConfig struct {
	Broker        *pam.Broker
	Sessions      *pam.SessionManager
	Hub           *gateway.SessionHub
	Store         gateway.ReplayStore
	CA            *gateway.SSHCertificateAuthority
	RecMaxBytes   int
	DialTimeout   time.Duration
	IdleTimeout   time.Duration
	MaxResultRows int
	// Now overrides the clock in tests.
	Now func() time.Time
}

// Bridge terminates browser web-SSH / web-database sessions and splices them
// onto governed PAM sessions. It holds no per-connection state; one Bridge is
// shared by every WebSocket the API serves.
type Bridge struct {
	broker        *pam.Broker
	sessions      *pam.SessionManager
	hub           *gateway.SessionHub
	store         gateway.ReplayStore
	ca            *gateway.SSHCertificateAuthority
	recMaxBytes   int
	dialTimeout   time.Duration
	idleTimeout   time.Duration
	maxResultRows int
	now           func() time.Time
}

// NewBridge validates the config and builds a Bridge.
func NewBridge(cfg BridgeConfig) (*Bridge, error) {
	if cfg.Broker == nil || cfg.Sessions == nil {
		return nil, errors.New("webaccess: bridge requires a broker and session manager")
	}
	dt := cfg.DialTimeout
	if dt <= 0 {
		dt = 15 * time.Second
	}
	mrr := cfg.MaxResultRows
	if mrr <= 0 {
		mrr = 1000
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Bridge{
		broker:        cfg.Broker,
		sessions:      cfg.Sessions,
		hub:           cfg.Hub,
		store:         cfg.Store,
		ca:            cfg.CA,
		recMaxBytes:   cfg.RecMaxBytes,
		dialTimeout:   dt,
		idleTimeout:   cfg.IdleTimeout,
		maxResultRows: mrr,
		now:           now,
	}, nil
}

// ServeParams carries the per-connection context the HTTP handler resolved
// before handing the socket to the bridge.
type ServeParams struct {
	// WorkspaceID is the workspace the WebSocket caller authenticated for (the
	// iam-core tenant resolved at the HTTP layer). The bridge pins the redeemed
	// session to it: a connect token can only be driven inside its own tenant,
	// even though the token is itself workspace-bound. uuid.Nil disables the
	// check (degraded boot with no validator); the token's own workspace
	// binding still governs.
	WorkspaceID uuid.UUID
	// RemoteAddr is the operator's client address, recorded on the session row.
	RemoteAddr string
}

// ServeSSH runs a web-SSH terminal session on conn.
func (b *Bridge) ServeSSH(ctx context.Context, conn wsConn, p ServeParams) {
	b.serve(ctx, conn, p, kindSSH)
}

// ServeDB runs a web-database console session on conn.
func (b *Bridge) ServeDB(ctx context.Context, conn wsConn, p ServeParams) {
	b.serve(ctx, conn, p, kindDB)
}

// serve is the shared lifecycle: read the hello/token, redeem it through the
// broker (lease validation + session open + audit), enforce tenant + protocol
// binding, wire recording/audit/takeover, dispatch the protocol loop, and tear
// everything down (flush recording, anchor its hash in the audit chain, close
// the session row).
func (b *Bridge) serve(ctx context.Context, conn wsConn, p ServeParams, k kind) {
	sender := newWSSender(conn, 10*time.Second)
	defer func() {
		sender.markClosed()
		_ = conn.Close()
	}()

	token, hello, err := b.readHello(conn)
	if err != nil {
		_ = sender.json(errorMessage{Type: msgError, Message: "expected a connect token"})
		return
	}

	leased, err := b.broker.RedeemConnectToken(ctx, token, p.RemoteAddr)
	if err != nil {
		_ = sender.json(errorMessage{Type: msgError, Message: "invalid or expired connect token"})
		logger.Warnf(ctx, "webaccess: redeem from %s failed: %v", p.RemoteAddr, err)
		return
	}
	session := leased.Session

	// Tenant isolation: the WebSocket caller's authenticated workspace must own
	// the session the token opened. A mismatch means a token was presented on a
	// connection authenticated for another tenant — refuse and reconcile the
	// just-opened session closed so it does not orphan active.
	if p.WorkspaceID != uuid.Nil && session.WorkspaceID != p.WorkspaceID {
		_ = sender.json(errorMessage{Type: msgError, Message: "connect token does not belong to this workspace"})
		b.reconcileOrphan(ctx, session)
		logger.Warnf(ctx, "webaccess: token workspace %s != caller workspace %s", session.WorkspaceID, p.WorkspaceID)
		return
	}

	if !protocolMatchesKind(leased.Target.Protocol, k) {
		_ = sender.json(errorMessage{Type: msgError, Message: "connect token is not for this access type"})
		b.reconcileOrphan(ctx, session)
		return
	}

	logger.Infof(ctx, "webaccess: session %s opened for %s → %s (%s)", session.ID, session.Subject, leased.Target.Address, leased.Target.Protocol)

	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	rec := gateway.NewIORecorder(sessCtx, session.ID.String(), b.recMaxBytes)
	if b.hub != nil {
		deregister := b.hub.Register(session.ID, session.WorkspaceID, session.Subject, rec, cancel)
		defer deregister()
	}
	defer b.teardown(ctx, session, rec)
	defer func() {
		_ = sender.json(statusMessage{Type: msgStatus, State: stateClosed})
	}()

	// Idle watchdog: sever a session that has exchanged no bytes for the
	// configured window so an abandoned browser tab does not hold the upstream
	// (and the lease window) open. Disabled when IdleTimeout <= 0.
	activity := newActivityClock(b.now)
	if b.idleTimeout > 0 {
		go b.watchIdle(sessCtx, cancel, rec, activity)
	}

	_ = sender.json(readyMessage{
		Type:           msgReady,
		SessionID:      session.ID.String(),
		Protocol:       leased.Target.Protocol,
		TargetName:     leased.Target.Name,
		TargetAddress:  leased.Target.Address,
		Subject:        session.Subject,
		Recording:      b.store != nil,
		PolicyGoverned: true,
	})

	switch k {
	case kindSSH:
		b.runSSH(sessCtx, cancel, conn, sender, leased, rec, hello, activity)
	case kindDB:
		b.runDB(sessCtx, cancel, conn, sender, leased, rec, activity)
	}
}

// readHello reads the first frame, which must be a JSON hello carrying the
// one-shot connect token. It bounds the wait with handshakeTimeout.
func (b *Bridge) readHello(conn wsConn) (token string, hello clientMessage, err error) {
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	_, data, err := conn.ReadMessage()
	if err != nil {
		return "", clientMessage{}, err
	}
	if err := json.Unmarshal(data, &hello); err != nil {
		return "", clientMessage{}, err
	}
	if hello.Type != msgHello || hello.Token == "" {
		return "", clientMessage{}, errors.New("webaccess: first frame must be a hello with a token")
	}
	// Clear the handshake deadline; the protocol loops manage their own.
	_ = conn.SetReadDeadline(time.Time{})
	return hello.Token, hello, nil
}

// teardown flushes the recording, anchors its integrity hash in the audit
// chain, and closes the session row. It runs on a context detached from the
// request so it completes even when the operator's connection (and ctx) is
// already gone, mirroring the gateway proxies' teardown defer.
func (b *Bridge) teardown(ctx context.Context, session *models.PAMSession, rec *gateway.IORecorder) {
	flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := rec.Flush(flushCtx, b.store); err != nil {
		logger.Warnf(ctx, "webaccess: flush replay %s: %v", session.ID, err)
	}
	if recording := rec.Recording(); recording.Stored {
		if err := b.sessions.RecordRecording(flushCtx, session, pam.RecordingRef{
			Key: recording.Key, SHA256: recording.SHA256, Bytes: recording.Bytes, Truncated: recording.Truncated,
		}); err != nil {
			logger.Warnf(ctx, "webaccess: record recording evidence %s: %v", session.ID, err)
		}
	}
	if err := b.sessions.CloseSession(flushCtx, session.WorkspaceID, session.ID); err != nil {
		logger.Warnf(ctx, "webaccess: close session %s: %v", session.ID, err)
	}
}

// reconcileOrphan closes a session whose token was already redeemed (consumed,
// row marked active) but whose proxy never started — a token presented on the
// wrong workspace or to the wrong access type. Without it the row would stay
// active forever with the one-shot token already spent.
func (b *Bridge) reconcileOrphan(ctx context.Context, session *models.PAMSession) {
	if session == nil {
		return
	}
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := b.sessions.CloseSession(closeCtx, session.WorkspaceID, session.ID); err != nil {
		logger.Warnf(ctx, "webaccess: reconcile orphaned session %s: %v", session.ID, err)
	}
}

// protocolMatchesKind reports whether a target protocol belongs to the access
// class the route serves.
func protocolMatchesKind(protocol string, k kind) bool {
	switch k {
	case kindSSH:
		return protocol == models.PAMProtocolSSH
	case kindDB:
		return protocol == models.PAMProtocolPostgres || protocol == models.PAMProtocolMySQL
	}
	return false
}

// activityClock tracks the last time bytes flowed in either direction, for the
// idle watchdog. It is updated from the read loop and the output pump and read
// by the watchdog, so it is guarded by an atomic.
type activityClock struct {
	now      func() time.Time
	lastNano atomic.Int64
}

func newActivityClock(now func() time.Time) *activityClock {
	a := &activityClock{now: now}
	a.lastNano.Store(now().UnixNano())
	return a
}

func (a *activityClock) touch() { a.lastNano.Store(a.now().UnixNano()) }

func (a *activityClock) idleFor() time.Duration {
	return a.now().Sub(time.Unix(0, a.lastNano.Load()))
}

// watchIdle cancels the session when it has been idle past the configured
// timeout. It annotates the recording so the transcript explains the teardown.
func (b *Bridge) watchIdle(ctx context.Context, cancel context.CancelFunc, rec *gateway.IORecorder, activity *activityClock) {
	// Check at a fraction of the timeout so the worst-case overshoot is small.
	interval := b.idleTimeout / 4
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if activity.idleFor() >= b.idleTimeout {
				rec.Annotate("[session closed: idle timeout]")
				rec.Interrupt()
				cancel()
				return
			}
		}
	}
}
