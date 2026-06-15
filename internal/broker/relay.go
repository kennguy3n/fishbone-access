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
// DialThroughAgent can reach a private target through the right agent's tunnel.
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

// agentConn is one live tunnel: the multiplexed session plus the agent's
// current reachable set (rebuilt on every (re-)registration).
type agentConn struct {
	identity AgentIdentity
	session  *yamux.Session

	mu    sync.RWMutex
	reach reachableSet
}

func (a *agentConn) setReach(rs reachableSet) {
	a.mu.Lock()
	a.reach = rs
	a.mu.Unlock()
}

func (a *agentConn) allows(addr string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.reach.allows(addr)
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

// applyRegister persists the registration and refreshes the in-memory reachable
// set as the union of the agent's self-reported specs and the operator-created
// bindings, then publishes the agent into the registry.
func (r *Relay) applyRegister(ctx context.Context, ac *agentConn, reg RegisterPayload) error {
	id := ac.identity
	if err := r.store.OnRegister(ctx, id.WorkspaceID, id.AgentID, reg); err != nil {
		return err
	}
	bindings, err := r.store.OperatorBindings(ctx, id.WorkspaceID, id.AgentID)
	if err != nil {
		return err
	}
	specs := append([]ReachableSpec{}, reg.Reachable...)
	specs = append(specs, bindings...)
	ac.setReach(newReachableSet(specs))
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

// DialThroughAgent opens a new stream to an online agent in workspaceID that
// advertises a path to targetAddr (host:port) and returns it as a net.Conn the
// gateway's protocol handlers use unchanged. It fails closed with
// ErrAgentUnavailable when no such agent is connected — and NEVER considers an
// agent in another workspace, so cross-tenant brokering is impossible.
func (r *Relay) DialThroughAgent(ctx context.Context, workspaceID uuid.UUID, targetAddr string) (net.Conn, error) {
	return r.dialThroughAgentAs(ctx, workspaceID, targetAddr, "")
}

// DialThroughAgentAs is DialThroughAgent with an explicit audit actor (the
// subject opening the privileged session), recorded on the broker-open event.
func (r *Relay) DialThroughAgentAs(ctx context.Context, workspaceID uuid.UUID, targetAddr, actor string) (net.Conn, error) {
	return r.dialThroughAgentAs(ctx, workspaceID, targetAddr, actor)
}

func (r *Relay) dialThroughAgentAs(ctx context.Context, workspaceID uuid.UUID, targetAddr, actor string) (net.Conn, error) {
	candidates := r.candidates(workspaceID, targetAddr)
	if len(candidates) == 0 {
		return nil, ErrAgentUnavailable
	}
	var lastErr error
	for _, ac := range candidates {
		// Re-check the agent is still live before opening a session, so a revoke
		// that landed after the tunnel came up fails the new session closed.
		if err := r.store.AuthorizeDial(ctx, workspaceID, ac.identity.AgentID); err != nil {
			lastErr = err
			continue
		}
		conn, err := r.openStream(ctx, ac, targetAddr)
		if err != nil {
			lastErr = err
			continue
		}
		// Best-effort audit; a failure to record must not drop a live session.
		if err := r.store.AuditBrokerOpen(context.WithoutCancel(ctx), workspaceID, ac.identity.AgentID, targetAddr, actor); err != nil {
			logger.Warnf(ctx, "broker: audit broker-open agent=%s: %v", ac.identity.AgentID, err)
		}
		return conn, nil
	}
	if lastErr == nil {
		lastErr = ErrAgentUnavailable
	}
	return nil, fmt.Errorf("broker: dial through agent: %w", lastErr)
}

// candidates returns the online agents in the workspace that advertise a path to
// addr (a snapshot copy so the dial loop holds no lock).
func (r *Relay) candidates(workspaceID uuid.UUID, addr string) []*agentConn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	byAgent := r.agents[workspaceID]
	if len(byAgent) == 0 {
		return nil
	}
	var out []*agentConn
	for _, ac := range byAgent {
		if ac.allows(addr) {
			out = append(out, ac)
		}
	}
	return out
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
