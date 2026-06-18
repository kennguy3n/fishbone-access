package broker

import (
	"context"
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// forwardDialActor identifies the source of a forwarded dial in the owning
// replica's broker-open audit. The owner performs the single authoritative
// revoke re-check and audit; a forward-only dialer never authorizes or audits
// itself (no double-audit), mirroring Relay.dialForward.
const forwardDialActor = "access-workflow-engine"

// ForwardOnlyDialer dials THROUGH an outbound connector agent from a process
// that holds no agent tunnels of its own — specifically the workflow engine,
// whose scheduled ACTIVE discovery sweep must reach targets via an agent whose
// tunnel terminates on a pam-gateway replica. It resolves the owning replica
// from the shared session directory and forwards the dial over the inter-replica
// mTLS forward plane, exactly like Relay.dialForward but WITHOUT any local
// fast-path (this process never owns a tunnel, so it never claims directory
// ownership and the self-owner guard is moot). It fails closed with
// ErrAgentUnavailable on any unknown/stale/unreachable owner — never a direct
// dial, never a different agent — preserving the broker's agent-only,
// fail-closed guarantee.
type ForwardOnlyDialer struct {
	dir SessionDirectory
	fwd *ForwardClient
}

// NewForwardOnlyDialer builds a forward-only dialer over a session directory and
// a forward client. Both are required; if either is nil every dial fails closed.
func NewForwardOnlyDialer(dir SessionDirectory, fwd *ForwardClient) *ForwardOnlyDialer {
	return &ForwardOnlyDialer{dir: dir, fwd: fwd}
}

// DialThroughAgent satisfies discovery.AgentDialer. It performs a single
// directory read and at most one forward dial, failing closed on every error or
// non-live owner so a scheduled sweep can never reach a target except through a
// live agent owned by a reachable gateway replica.
func (d *ForwardOnlyDialer) DialThroughAgent(ctx context.Context, workspaceID, agentID uuid.UUID, targetAddr string) (net.Conn, error) {
	if d == nil || d.dir == nil || d.fwd == nil {
		return nil, ErrAgentUnavailable
	}
	if workspaceID == uuid.Nil || agentID == uuid.Nil {
		return nil, ErrAgentUnavailable
	}
	entry, fresh, err := d.dir.Lookup(ctx, workspaceID, agentID)
	if err != nil {
		// Source of truth unreachable: fail closed, never guess an owner.
		logger.Warnf(ctx, "broker: forward-only directory lookup agent=%s: %v", agentID, err)
		return nil, ErrAgentUnavailable
	}
	// Owner unknown, stale (crashed replica, no heartbeat), or missing its
	// forward address: all fail closed.
	if entry == nil || !fresh || entry.ForwardAddr == "" {
		return nil, ErrAgentUnavailable
	}
	conn, err := d.fwd.Dial(ctx, entry.ForwardAddr, workspaceID, agentID, targetAddr, forwardDialActor)
	if err != nil {
		// Bounded by the forward client's dial timeout, so a dead owner fails
		// closed promptly rather than hanging the sweep.
		logger.Warnf(ctx, "broker: forward-only dial agent=%s owner=%s: %v", agentID, entry.NodeID, err)
		return nil, ErrAgentUnavailable
	}
	return conn, nil
}

// DialBudget reports the forward client's dial timeout so a caller can use it as
// the OUTER dial deadline instead of a tighter per-call default. It satisfies
// discovery's optional DialBudgeter seam: the active sweep's probeOne wraps each
// dial in a short direct-probe timeout, but the multi-hop forward path (directory
// lookup → owner-replica TCP+mTLS → forward req/resp → agent dial) legitimately
// needs the wider ForwardTimeout. Without advertising it, the forward client's
// own 15s child context would be capped by probeOne's 3s parent (context only
// shortens, never extends), leaving ForwardTimeout inert. Returns 0 when no
// forward client is wired, so probeOne falls back to its probe timeout.
func (d *ForwardOnlyDialer) DialBudget() time.Duration {
	if d == nil || d.fwd == nil {
		return 0
	}
	return d.fwd.DialTimeout()
}
