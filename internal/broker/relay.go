package broker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/yamux"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// Relay is the control-plane endpoint outbound agents dial into. It terminates
// mTLS, binds each verified tunnel to its agent row, multiplexes session streams
// over it with yamux, and tracks which agents are online per workspace so
// DialThroughAgent routes a privileged session through the specific agent a
// target is bound to (its ViaAgentID), within the target's workspace.
//
// A Relay is a gateway ConnHandler: the pam-gateway supervisor accepts plain TCP
// on the relay port and hands each connection to Handle, which performs the TLS
// handshake itself (so the same supervisor lifecycle, drain, and accept loop the
// protocol proxies use apply unchanged).
type Relay struct {
	store     RelayStore
	tlsConfig *tls.Config
	yamuxCfg  *yamux.Config
	dialTO    time.Duration
	now       func() time.Time

	mu     sync.RWMutex
	agents map[uuid.UUID]map[uuid.UUID]*agentConn // workspaceID -> agentID -> conn
}

// agentConn is one live tunnel: the multiplexed session bound to its agent
// identity. Routing is by agent identity (the target's ViaAgentID), not by
// matching a reachable set, so a binding is a strict directive, not a hint.
type agentConn struct {
	identity AgentIdentity
	session  *yamux.Session
}

// RelayOption tunes a Relay.
type RelayOption func(*Relay)

// WithDialTimeout overrides the per-dial timeout (stream open + handshake).
func WithDialTimeout(d time.Duration) RelayOption {
	return func(r *Relay) {
		if d > 0 {
			r.dialTO = d
		}
	}
}

// WithClock overrides the clock (tests).
func WithClock(now func() time.Time) RelayOption {
	return func(r *Relay) {
		if now != nil {
			r.now = now
		}
	}
}

// NewRelay builds a Relay. serverTLS MUST require and verify client
// certificates against the agent CA pool (NewRelayServerTLS builds exactly
// that); Handle re-derives identity from the verified peer certificate.
func NewRelay(store RelayStore, serverTLS *tls.Config, opts ...RelayOption) *Relay {
	ycfg := yamux.DefaultConfig()
	// Quiet yamux's internal logging; the relay logs lifecycle events itself.
	ycfg.LogOutput = nil
	ycfg.Logger = noopLogger{}
	// Keepalive lets the relay notice a silently dropped agent (NAT timeout,
	// host crash) promptly and mark it offline rather than holding a dead entry.
	ycfg.EnableKeepAlive = true
	ycfg.KeepAliveInterval = 30 * time.Second
	r := &Relay{
		store:     store,
		tlsConfig: serverTLS,
		yamuxCfg:  ycfg,
		dialTO:    15 * time.Second,
		now:       time.Now,
		agents:    make(map[uuid.UUID]map[uuid.UUID]*agentConn),
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// NewRelayServerTLS builds the relay's server TLS config: it presents
// serverCert and requires+verifies an agent client certificate against the
// agent CA pool, so an unverified peer never reaches the yamux layer.
func NewRelayServerTLS(serverCert tls.Certificate, ca *AgentCA) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.Pool(),
		MinVersion:   tls.VersionTLS12,
	}
}

// Handle implements the gateway ConnHandler contract: it owns conn and returns
// when the tunnel ends or ctx is cancelled.
func (r *Relay) Handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	tlsConn := tls.Server(conn, r.tlsConfig)
	hsCtx, cancel := context.WithTimeout(ctx, r.dialTO)
	err := tlsConn.HandshakeContext(hsCtx)
	cancel()
	if err != nil {
		logger.Warnf(ctx, "broker: relay handshake failed from %s: %v", conn.RemoteAddr(), err)
		return
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		logger.Warnf(ctx, "broker: relay connection presented no client certificate")
		return
	}
	identity, err := IdentityFromCert(state.PeerCertificates[0])
	if err != nil {
		logger.Warnf(ctx, "broker: relay identity rejected: %v", err)
		return
	}
	if _, err := r.store.AuthorizeConnect(ctx, identity); err != nil {
		logger.Warnf(ctx, "broker: relay authorize agent=%s workspace=%s: %v", identity.AgentID, identity.WorkspaceID, err)
		return
	}

	session, err := yamux.Server(tlsConn, r.yamuxCfg)
	if err != nil {
		logger.Warnf(ctx, "broker: yamux server: %v", err)
		return
	}
	defer func() { _ = session.Close() }()

	// The agent opens exactly one control stream first.
	control, err := session.Accept()
	if err != nil {
		logger.Warnf(ctx, "broker: accept control stream agent=%s: %v", identity.AgentID, err)
		return
	}

	ac := &agentConn{identity: identity, session: session}
	logger.Infof(ctx, "broker: agent online workspace=%s agent=%s addr=%s", identity.WorkspaceID, identity.AgentID, conn.RemoteAddr())
	r.serveControl(ctx, ac, control)
}

// serveControl reads the agent's control stream: the initial register, then
// heartbeats / re-registrations, keeping the registry and the durable health
// view in sync until the stream ends.
func (r *Relay) serveControl(ctx context.Context, ac *agentConn, control net.Conn) {
	id := ac.identity
	scanner := scanControl(control)
	registered := false
	defer func() {
		if registered {
			r.deregister(ac)
			if err := r.store.OnDisconnect(context.WithoutCancel(ctx), id.WorkspaceID, id.AgentID); err != nil {
				logger.Warnf(ctx, "broker: mark agent offline agent=%s: %v", id.AgentID, err)
			}
			logger.Infof(ctx, "broker: agent offline workspace=%s agent=%s", id.WorkspaceID, id.AgentID)
		}
	}()

	// Stop scanning when ctx is cancelled by closing the control stream.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = control.Close()
		case <-stop:
		}
	}()

	for scanner.Scan() {
		var msg ControlMessage
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			logger.Warnf(ctx, "broker: bad control message agent=%s: %v", id.AgentID, err)
			continue
		}
		switch msg.Type {
		case ControlTypeRegister:
			reg := RegisterPayload{}
			if msg.Register != nil {
				reg = *msg.Register
			}
			if err := r.applyRegister(ctx, ac, reg); err != nil {
				logger.Warnf(ctx, "broker: register agent=%s: %v", id.AgentID, err)
				return
			}
			registered = true
		case ControlTypeHeartbeat:
			if err := r.store.OnHeartbeat(ctx, id.WorkspaceID, id.AgentID); err != nil {
				logger.Warnf(ctx, "broker: heartbeat agent=%s: %v", id.AgentID, err)
			}
		default:
			logger.Warnf(ctx, "broker: unknown control type %q agent=%s", msg.Type, id.AgentID)
		}
	}
}

// applyRegister persists the registration (self-reported reachable specs are
// stored for the operator-facing UI) and publishes the agent into the registry
// so DialThroughAgent can route to it by identity.
func (r *Relay) applyRegister(ctx context.Context, ac *agentConn, reg RegisterPayload) error {
	id := ac.identity
	if err := r.store.OnRegister(ctx, id.WorkspaceID, id.AgentID, reg); err != nil {
		return err
	}
	r.register(ac)
	return nil
}

func (r *Relay) register(ac *agentConn) {
	id := ac.identity
	r.mu.Lock()
	defer r.mu.Unlock()
	byAgent := r.agents[id.WorkspaceID]
	if byAgent == nil {
		byAgent = make(map[uuid.UUID]*agentConn)
		r.agents[id.WorkspaceID] = byAgent
	}
	byAgent[id.AgentID] = ac
}

func (r *Relay) deregister(ac *agentConn) {
	id := ac.identity
	r.mu.Lock()
	defer r.mu.Unlock()
	byAgent := r.agents[id.WorkspaceID]
	if byAgent == nil {
		return
	}
	// Only remove if it is still the same connection (a reconnect may have
	// replaced it).
	if byAgent[id.AgentID] == ac {
		delete(byAgent, id.AgentID)
	}
	if len(byAgent) == 0 {
		delete(r.agents, id.WorkspaceID)
	}
}

// DialThroughAgent opens a new stream to the agent identified by agentID in
// workspaceID and returns it as a net.Conn the gateway's protocol handlers use
// unchanged. Routing is strict: it dials through exactly the agent the target
// is bound to (its ViaAgentID) and NEVER falls back to another agent, so a
// binding is an authoritative routing directive rather than a reachability
// hint. It fails closed with ErrAgentUnavailable when that agent is not
// connected — and only ever looks within workspaceID, so cross-tenant
// brokering is impossible.
func (r *Relay) DialThroughAgent(ctx context.Context, workspaceID, agentID uuid.UUID, targetAddr string) (net.Conn, error) {
	return r.dialThroughAgentAs(ctx, workspaceID, agentID, targetAddr, "")
}

// DialThroughAgentAs is DialThroughAgent with an explicit audit actor (the
// subject opening the privileged session), recorded on the broker-open event.
func (r *Relay) DialThroughAgentAs(ctx context.Context, workspaceID, agentID uuid.UUID, targetAddr, actor string) (net.Conn, error) {
	return r.dialThroughAgentAs(ctx, workspaceID, agentID, targetAddr, actor)
}

func (r *Relay) dialThroughAgentAs(ctx context.Context, workspaceID, agentID uuid.UUID, targetAddr, actor string) (net.Conn, error) {
	if workspaceID == uuid.Nil || agentID == uuid.Nil {
		return nil, ErrAgentUnavailable
	}
	ac := r.lookup(workspaceID, agentID)
	if ac == nil {
		return nil, ErrAgentUnavailable
	}
	// Re-check the agent is still live before opening a session, so a revoke
	// that landed after the tunnel came up fails the new session closed.
	if err := r.store.AuthorizeDial(ctx, workspaceID, agentID); err != nil {
		return nil, fmt.Errorf("broker: dial through agent: %w", err)
	}
	conn, err := r.openStream(ctx, ac, targetAddr)
	if err != nil {
		return nil, fmt.Errorf("broker: dial through agent: %w", err)
	}
	// Best-effort audit; a failure to record must not drop a live session.
	if err := r.store.AuditBrokerOpen(context.WithoutCancel(ctx), workspaceID, agentID, targetAddr, actor); err != nil {
		logger.Warnf(ctx, "broker: audit broker-open agent=%s: %v", agentID, err)
	}
	return conn, nil
}

// lookup returns the live tunnel for a specific agent in a workspace, or nil if
// that agent is not currently connected (scoped to workspaceID so a foreign
// agent is never reachable).
func (r *Relay) lookup(workspaceID, agentID uuid.UUID) *agentConn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.agents[workspaceID][agentID]
}

// openStream opens a yamux stream to the agent, performs the dial handshake, and
// returns the stream as the raw byte tunnel once the agent confirms it reached
// the upstream.
func (r *Relay) openStream(ctx context.Context, ac *agentConn, targetAddr string) (net.Conn, error) {
	stream, err := ac.session.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	deadline := r.now().Add(r.dialTO)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = stream.SetDeadline(deadline)
	if err := writeJSONLine(stream, DialRequest{Target: targetAddr}); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("send dial request: %w", err)
	}
	var resp DialResponse
	if err := readJSONLine(stream, &resp); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("read dial response: %w", err)
	}
	if !resp.OK {
		_ = stream.Close()
		return nil, fmt.Errorf("agent refused dial: %s", resp.Error)
	}
	// Clear the handshake deadline so the live session is not torn down mid-use.
	_ = stream.SetDeadline(time.Time{})
	return stream, nil
}

// OnlineCount reports how many agents are currently online for a workspace
// (used by the API health surface and tests).
func (r *Relay) OnlineCount(workspaceID uuid.UUID) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.agents[workspaceID])
}

// IsOnline reports whether a specific agent currently holds a live tunnel.
func (r *Relay) IsOnline(workspaceID, agentID uuid.UUID) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.agents[workspaceID][agentID]
	return ok
}

var _ interface {
	Handle(context.Context, net.Conn)
} = (*Relay)(nil)

// noopLogger satisfies yamux's logger interface without emitting anything.
type noopLogger struct{}

func (noopLogger) Print(...any)          {}
func (noopLogger) Printf(string, ...any) {}
func (noopLogger) Println(...any)        {}
