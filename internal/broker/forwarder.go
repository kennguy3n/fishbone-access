package broker

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// Cross-replica forward plane.
//
// When DialThroughAgent runs on a replica that does NOT hold an agent's tunnel
// locally, the relay looks the owner up in the session directory and asks it,
// over an internal replica-to-replica mTLS connection, to open the agent stream
// on its behalf. The owner opens the local yamux stream and the two replicas
// relay raw bytes, so the calling replica gets a net.Conn indistinguishable (to
// the protocol proxies) from a locally brokered stream.
//
// Invariants preserved across the forward:
//   - Workspace scoping: the owner only serves agents it actually holds, looked
//     up workspace-scoped, so a forwarded dial can never cross a tenant.
//   - Revoke re-check (AuthorizeDial) runs authoritatively AT THE OWNER, right
//     before the agent stream opens — the same point a local dial checks it.
//   - Exactly one AuditBrokerOpen per session: the owner (which opens the agent
//     stream) audits; the calling replica does NOT, so a forwarded dial produces
//     one broker-open event, never zero and never two.
//   - The forward dial is bounded by the relay's dial timeout, so a dial against
//     a crashed owner fails closed instead of hanging.

// ForwardRequest is sent by the calling replica on a freshly handshaked forward
// connection, asking the owner to open a stream to the agent it holds.
type ForwardRequest struct {
	WorkspaceID uuid.UUID `json:"workspace_id"`
	AgentID     uuid.UUID `json:"agent_id"`
	Target      string    `json:"target"`
	// Actor is the subject opening the privileged session, propagated so the
	// owner records it on the single broker-open audit event.
	Actor string `json:"actor"`
}

// ForwardResponse is the owner's reply. When OK is true the rest of the
// connection is the raw, bidirectional byte tunnel relayed to the agent stream;
// otherwise Error explains the closed failure and the connection is closed.
type ForwardResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Forwarder is the owner-side handler of the internal forward listener. It is a
// gateway ConnHandler (Handle(ctx, conn)) so the pam-gateway supervisor accepts,
// drains, and tracks it exactly like the agent relay and the protocol proxies.
// It serves forwarded dial requests by opening a stream to a LOCAL agent tunnel.
type Forwarder struct {
	relay *Relay
	tls   *ForwardTLS
}

// NewForwarder builds the owner-side forward handler over the relay's local
// tunnel map and the inter-replica mTLS config.
func NewForwarder(relay *Relay, ftls *ForwardTLS) *Forwarder {
	return &Forwarder{relay: relay, tls: ftls}
}

var _ interface {
	Handle(context.Context, net.Conn)
} = (*Forwarder)(nil)

// Handle terminates the inter-replica mTLS, reads one ForwardRequest, opens the
// requested LOCAL agent stream (re-checking authorization at this owner), and
// relays bytes until either side closes. It owns conn and returns when the
// relayed session ends or ctx is cancelled.
func (f *Forwarder) Handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	tlsConn := tls.Server(conn, f.tls.ServerConfig())
	hsCtx, cancel := context.WithTimeout(ctx, f.relay.dialTO)
	err := tlsConn.HandshakeContext(hsCtx)
	cancel()
	if err != nil {
		logger.Warnf(ctx, "broker: forward handshake failed from %s: %v", conn.RemoteAddr(), err)
		return
	}

	// Bound the request/response handshake by the dial timeout; the live tunnel
	// runs with no deadline afterwards so a long session is not torn down.
	deadline := f.relay.now().Add(f.relay.dialTO)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = tlsConn.SetDeadline(deadline)

	var req ForwardRequest
	if err := readJSONLine(tlsConn, &req); err != nil {
		logger.Warnf(ctx, "broker: forward read request: %v", err)
		return
	}
	if req.WorkspaceID == uuid.Nil || req.AgentID == uuid.Nil {
		_ = writeJSONLine(tlsConn, ForwardResponse{OK: false, Error: "invalid request"})
		return
	}

	// The directory pointed the caller here, but ownership may have moved between
	// that read and now. We can only serve an agent whose tunnel we still hold
	// locally; if we no longer do, fail closed (the caller surfaces
	// ErrAgentUnavailable) rather than guessing.
	ac := f.relay.lookup(req.WorkspaceID, req.AgentID)
	if ac == nil {
		_ = writeJSONLine(tlsConn, ForwardResponse{OK: false, Error: "agent not owned here"})
		return
	}
	// Authoritative revoke re-check AT THE OWNER, immediately before opening the
	// agent stream — identical to the local dial path.
	if err := f.relay.store.AuthorizeDial(ctx, req.WorkspaceID, req.AgentID); err != nil {
		_ = writeJSONLine(tlsConn, ForwardResponse{OK: false, Error: "agent unavailable"})
		return
	}
	stream, err := f.relay.openStream(ctx, ac, req.Target)
	if err != nil {
		_ = writeJSONLine(tlsConn, ForwardResponse{OK: false, Error: "open stream failed"})
		return
	}
	defer stream.Close()

	// The owner opens the agent stream, so the owner records the SINGLE
	// broker-open audit event (the calling replica must not, to avoid a double
	// audit). Best-effort: a failed append must not drop a live session.
	if err := f.relay.store.AuditBrokerOpen(context.WithoutCancel(ctx), req.WorkspaceID, req.AgentID, req.Target, req.Actor); err != nil {
		logger.Warnf(ctx, "broker: forward audit broker-open agent=%s: %v", req.AgentID, err)
	}

	if err := writeJSONLine(tlsConn, ForwardResponse{OK: true}); err != nil {
		logger.Warnf(ctx, "broker: forward write response: %v", err)
		return
	}
	// Live tunnel: clear the handshake deadline and relay bytes both ways until
	// either end closes or ctx is cancelled.
	_ = tlsConn.SetDeadline(time.Time{})
	relayBytes(ctx, tlsConn, stream)
}

// ForwardClient is the calling-replica side: it dials an owner's forward
// listener, negotiates the forward handshake, and returns the live relayed
// connection as a net.Conn the protocol proxies consume unchanged.
type ForwardClient struct {
	tls    *ForwardTLS
	dialTO time.Duration
}

// NewForwardClient builds the caller-side forward dialer. dialTO bounds the
// whole forward setup (TCP connect + TLS handshake + request/response) so a dial
// against a crashed or unreachable owner fails closed promptly.
func NewForwardClient(ftls *ForwardTLS, dialTO time.Duration) *ForwardClient {
	if dialTO <= 0 {
		dialTO = 15 * time.Second
	}
	return &ForwardClient{tls: ftls, dialTO: dialTO}
}

// Dial opens a relayed stream to the agent via its owning replica at ownerAddr.
// The returned net.Conn carries the live tunnel; the caller does NOT audit (the
// owner already did). On any failure it returns an error so the relay surfaces
// ErrAgentUnavailable, never a fallback path.
func (c *ForwardClient) Dial(ctx context.Context, ownerAddr string, workspaceID, agentID uuid.UUID, target, actor string) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, c.dialTO)
	defer cancel()

	var d net.Dialer
	raw, err := d.DialContext(dctx, "tcp", ownerAddr)
	if err != nil {
		return nil, fmt.Errorf("forward dial owner %s: %w", ownerAddr, err)
	}
	tlsConn := tls.Client(raw, c.tls.ClientConfig())
	if err := tlsConn.HandshakeContext(dctx); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("forward handshake owner %s: %w", ownerAddr, err)
	}
	// Bound the handshake exchange; cleared once the owner confirms OK so the
	// live session is not torn down mid-use.
	if deadline, ok := dctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	}
	if err := writeJSONLine(tlsConn, ForwardRequest{
		WorkspaceID: workspaceID,
		AgentID:     agentID,
		Target:      target,
		Actor:       actor,
	}); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("forward send request: %w", err)
	}
	var resp ForwardResponse
	if err := readJSONLine(tlsConn, &resp); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("forward read response: %w", err)
	}
	if !resp.OK {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("forward refused by owner: %s", resp.Error)
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// relayBytes copies bytes bidirectionally between the inter-replica connection
// and the local agent stream until either side closes (or ctx is cancelled),
// then unblocks both directions. It is the byte pump that makes a forwarded dial
// behave like a local one.
func relayBytes(ctx context.Context, a, b net.Conn) {
	done := make(chan struct{})
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = a.SetDeadline(time.Now())
			_ = b.SetDeadline(time.Now())
		case <-stop:
		}
	}()

	var once sync.Once
	closeBoth := func() {
		// Unblock the other Copy by deadlining both ends; a half-closed stream
		// must not leave the peer direction hanging on a dead session.
		_ = a.SetDeadline(time.Now())
		_ = b.SetDeadline(time.Now())
	}
	go func() {
		_, _ = io.Copy(a, b)
		once.Do(closeBoth)
		close(done)
	}()
	_, _ = io.Copy(b, a)
	once.Do(closeBoth)
	<-done
}
