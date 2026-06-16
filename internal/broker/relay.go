package broker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
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

	// Cross-replica HA (all nil/empty unless WithCrossReplica is set, so a
	// single-replica or test deployment behaves exactly as before): dir is the
	// durable owner directory, fwd dials a peer replica's forward listener,
	// nodeID identifies this replica and forwardAddr is the internal address
	// peers dial to reach the tunnels this replica owns.
	dir         SessionDirectory
	fwd         *ForwardClient
	nodeID      string
	forwardAddr string

	mu     sync.RWMutex
	agents map[uuid.UUID]map[uuid.UUID]*agentConn // workspaceID -> agentID -> conn
}

// agentConn is one live tunnel: the multiplexed session bound to its agent
// identity. Routing is by agent identity (the target's ViaAgentID), not by
// matching a reachable set, so a binding is a strict directive, not a hint.
type agentConn struct {
	identity AgentIdentity
	session  *yamux.Session
	// ownerEpoch is the session-directory generation this connection claimed on
	// register (0 when no directory is wired). Heartbeat refresh and disconnect
	// release are conditioned on it so a superseded owner cannot clobber a newer
	// claim (epoch CAS).
	ownerEpoch int64
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

// WithCrossReplica enables the HA path: the relay claims/refreshes/releases
// ownership of its tunnels in the shared session directory and, when a dial
// lands here for an agent owned by ANOTHER replica, forwards it to that owner
// via fwd. nodeID is this replica's identity (defaulted to hostname by the
// caller) and forwardAddr is the internal address peers dial to reach it. When
// any of dir/fwd/forwardAddr is unset the relay stays single-replica and a
// non-local agent fails closed exactly as before.
func WithCrossReplica(dir SessionDirectory, fwd *ForwardClient, nodeID, forwardAddr string) RelayOption {
	return func(r *Relay) {
		r.dir = dir
		r.fwd = fwd
		r.nodeID = nodeID
		r.forwardAddr = forwardAddr
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
	// ownershipLost is set when a heartbeat's CAS reveals another replica took
	// over this agent (it reconnected elsewhere). In that case the agent is NOT
	// offline — its tunnel merely migrated — so we must drop our local tunnel
	// WITHOUT touching shared state: the new owner already marked it online, and
	// emitting OnDisconnect here would both flip its status to offline and append
	// a misleading AgentOffline event to the immutable audit chain. The directory
	// row and its ownership likewise belong to the new owner now (our Release CAS
	// would no-op anyway), so we leave them untouched.
	ownershipLost := false
	defer func() {
		if registered {
			r.deregister(ac)
			if ownershipLost {
				logger.Infof(ctx, "broker: tunnel migrated to another replica workspace=%s agent=%s", id.WorkspaceID, id.AgentID)
				return
			}
			// Clear our directory ownership so peers stop forwarding to a tunnel
			// we no longer hold. CAS-conditioned on (node, epoch) so a superseded
			// owner can never delete a newer owner's claim.
			if r.dir != nil && ac.ownerEpoch != 0 {
				if err := r.dir.Release(context.WithoutCancel(ctx), id.WorkspaceID, id.AgentID, r.nodeID, ac.ownerEpoch); err != nil {
					logger.Warnf(ctx, "broker: release ownership agent=%s: %v", id.AgentID, err)
				}
			}
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
				if errors.Is(err, ErrAgentUnavailable) {
					// The agent was revoked while connected: drop its tunnel now
					// (returning runs the deferred deregister + session close), so
					// any in-progress brokered sessions cannot outlive the revoke
					// beyond a single heartbeat interval.
					logger.Infof(ctx, "broker: dropping revoked agent tunnel workspace=%s agent=%s", id.WorkspaceID, id.AgentID)
					return
				}
				logger.Warnf(ctx, "broker: heartbeat agent=%s: %v", id.AgentID, err)
			}
			// Coalesced directory maintenance (heartbeat only, never per-dial).
			if r.dir != nil && r.forwardAddr != "" {
				if ac.ownerEpoch == 0 {
					// We hold no ownership epoch: the initial Claim at register
					// failed (e.g. a transient Postgres error), so a Refresh has
					// nothing to update. Retry the Claim here so a registered agent
					// becomes forward-reachable on the next heartbeat instead of
					// waiting for a full reconnect.
					if epoch, err := r.dir.Claim(ctx, id.WorkspaceID, id.AgentID, r.nodeID, r.forwardAddr); err != nil {
						logger.Warnf(ctx, "broker: re-claim ownership agent=%s: %v", id.AgentID, err)
					} else {
						ac.ownerEpoch = epoch
					}
				} else if err := r.dir.Refresh(ctx, id.WorkspaceID, id.AgentID, r.nodeID, ac.ownerEpoch); err != nil {
					// A lost CAS means the agent reconnected to another replica that
					// took over — drop this now-stale tunnel.
					if errors.Is(err, ErrOwnershipLost) {
						logger.Infof(ctx, "broker: ownership lost, dropping stale tunnel workspace=%s agent=%s", id.WorkspaceID, id.AgentID)
						ownershipLost = true
						return
					}
					logger.Warnf(ctx, "broker: refresh ownership agent=%s: %v", id.AgentID, err)
				}
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
	// Claim cross-replica ownership of this tunnel (coalesced — register only,
	// never per-dial). A reconnect anywhere takes over via epoch CAS. Failure is
	// fail-open relative to the LOCAL tunnel (which works regardless), matching
	// the house posture for cross-replica state: ownerEpoch stays 0 and the next
	// heartbeat retries the Claim (see serveControl), so we just won't be
	// reachable by forwarding for at most one heartbeat interval.
	if r.dir != nil && r.forwardAddr != "" {
		epoch, err := r.dir.Claim(ctx, id.WorkspaceID, id.AgentID, r.nodeID, r.forwardAddr)
		if err != nil {
			logger.Warnf(ctx, "broker: claim ownership agent=%s: %v", id.AgentID, err)
		} else {
			ac.ownerEpoch = epoch
		}
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
	// Local fast-path: if this replica holds the tunnel, dial it exactly as
	// before — a pure in-memory lookup with ZERO new DB round-trips, which is the
	// common case and the one that must stay cheap at 5k-tenant scale.
	if ac := r.lookup(workspaceID, agentID); ac != nil {
		return r.dialLocal(ctx, ac, workspaceID, agentID, targetAddr, actor)
	}
	// Not local. Without the HA path wired, fail closed exactly as today.
	if !r.crossReplica() {
		return nil, ErrAgentUnavailable
	}
	return r.dialForward(ctx, workspaceID, agentID, targetAddr, actor)
}

// crossReplica reports whether the directory + forwarder HA path is wired.
func (r *Relay) crossReplica() bool {
	return r.dir != nil && r.fwd != nil && r.forwardAddr != ""
}

// dialLocal opens a stream through a tunnel THIS replica holds: the authoritative
// revoke re-check, the agent stream open, and the single broker-open audit all
// happen here.
func (r *Relay) dialLocal(ctx context.Context, ac *agentConn, workspaceID, agentID uuid.UUID, targetAddr, actor string) (net.Conn, error) {
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

// dialForward routes a dial to the replica that owns the agent's tunnel. It does
// a single directory read and at most one forward dial; the owner performs the
// revoke re-check and the single broker-open audit, so this path neither
// authorizes nor audits (no double-audit). It fails closed with
// ErrAgentUnavailable on any unknown/stale/unreachable owner — never a fallback
// to a different agent, never a direct dial.
func (r *Relay) dialForward(ctx context.Context, workspaceID, agentID uuid.UUID, targetAddr, actor string) (net.Conn, error) {
	entry, fresh, err := r.dir.Lookup(ctx, workspaceID, agentID)
	if err != nil {
		// Source of truth unreachable: fail closed, never guess an owner.
		logger.Warnf(ctx, "broker: directory lookup agent=%s: %v", agentID, err)
		return nil, ErrAgentUnavailable
	}
	// Owner unknown, stale (crashed replica, no heartbeat), missing its forward
	// address, or — defensively — pointing back at this node even though we have
	// no local tunnel (ours just dropped): all fail closed.
	if entry == nil || !fresh || entry.ForwardAddr == "" || entry.NodeID == r.nodeID {
		return nil, ErrAgentUnavailable
	}
	conn, err := r.fwd.Dial(ctx, entry.ForwardAddr, workspaceID, agentID, targetAddr, actor)
	if err != nil {
		// Bounded by the forward client's dial timeout, so a dead owner fails
		// closed promptly rather than hanging the caller.
		logger.Warnf(ctx, "broker: forward dial agent=%s owner=%s: %v", agentID, entry.NodeID, err)
		return nil, ErrAgentUnavailable
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

// directoryReadTimeout bounds the management-surface directory reads
// (OnlineCount / IsOnline) so a stalled database pool degrades to the local-map
// fallback instead of blocking the health surface indefinitely. These are not
// on the hot dial path, so a generous bound is fine.
const directoryReadTimeout = 5 * time.Second

// OnlineCount reports how many agents are online for a workspace. With the HA
// directory wired it reflects GLOBAL state (agents online on any replica),
// reading the directory's fresh-owner count; it falls back to the local map if
// the directory is unavailable so the surface degrades safely rather than
// reporting zero. Without the directory it is the local count, as before.
func (r *Relay) OnlineCount(workspaceID uuid.UUID) int {
	if r.dir != nil {
		ctx, cancel := context.WithTimeout(context.Background(), directoryReadTimeout)
		defer cancel()
		if n, err := r.dir.OnlineCount(ctx, workspaceID); err == nil {
			return n
		} else {
			logger.Warnf(context.Background(), "broker: directory online-count workspace=%s: %v", workspaceID, err)
		}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.agents[workspaceID])
}

// IsOnline reports whether a specific agent is online. The local tunnel map is
// authoritative for THIS replica (and the zero-DB fast-path); when the agent is
// not local and the HA directory is wired, it reflects global state so the
// Agents UI shows an agent as online regardless of which replica pins it.
func (r *Relay) IsOnline(workspaceID, agentID uuid.UUID) bool {
	r.mu.RLock()
	_, local := r.agents[workspaceID][agentID]
	r.mu.RUnlock()
	if local {
		return true
	}
	if r.dir == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), directoryReadTimeout)
	defer cancel()
	online, err := r.dir.IsOnline(ctx, workspaceID, agentID)
	if err != nil {
		logger.Warnf(context.Background(), "broker: directory is-online agent=%s: %v", agentID, err)
		return false
	}
	return online
}

var _ interface {
	Handle(context.Context, net.Conn)
} = (*Relay)(nil)

// noopLogger satisfies yamux's logger interface without emitting anything.
type noopLogger struct{}

func (noopLogger) Print(...any)          {}
func (noopLogger) Printf(string, ...any) {}
func (noopLogger) Println(...any)        {}
