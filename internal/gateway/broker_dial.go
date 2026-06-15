// Package gateway: brokered-dial seam.
//
// Every protocol proxy ultimately needs a raw transport connection to the PAM
// target before it layers SSH/Postgres/MySQL/... on top. Historically each one
// dialed target.Address directly, which requires the gateway to have network
// line-of-sight to the customer's host. This file introduces a single seam —
// the TargetDialer — that the proxies call instead of net.Dial, so a target can
// be reached EITHER directly (the unchanged default) OR through an outbound
// connector agent's tunnel (when the target is flagged "via agent"), with no
// further change to the protocol-specific code.
package gateway

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// TargetDialer establishes the raw transport connection to a PAM target. The
// returned net.Conn is what a protocol proxy wraps (an SSH transport, a
// Postgres startup stream, ...). Implementations decide whether that connection
// is a direct dial or a stream brokered through an agent's outbound tunnel.
type TargetDialer interface {
	DialTarget(ctx context.Context, target *models.PAMTarget) (net.Conn, error)
}

// AgentRelay is the slice of the broker the gateway depends on: open a stream to
// an online agent in a workspace that can reach an address. *broker.Relay
// satisfies it. Declared here as an interface so the gateway package does not
// hard-depend on the broker implementation and stays unit-testable with a fake.
type AgentRelay interface {
	DialThroughAgentAs(ctx context.Context, workspaceID uuid.UUID, targetAddr, actor string) (net.Conn, error)
}

// directDialer dials target.Address directly with a bounded timeout. It is the
// legacy behaviour, preserved exactly so targets not flagged for an agent dial
// identically to before this seam existed.
type directDialer struct {
	timeout time.Duration
}

// NewDirectDialer returns a TargetDialer that always dials directly.
func NewDirectDialer(timeout time.Duration) TargetDialer {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return directDialer{timeout: timeout}
}

func (d directDialer) DialTarget(ctx context.Context, target *models.PAMTarget) (net.Conn, error) {
	dialer := net.Dialer{Timeout: d.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", target.Address)
	if err != nil {
		return nil, fmt.Errorf("gateway: dial %s: %w", target.Address, err)
	}
	return conn, nil
}

// brokerDialer routes targets flagged ViaAgentID through the relay's tunnel and
// dials every other target directly. Fail-closed: a target marked "via agent"
// is NEVER silently dialed directly, so a misconfiguration cannot leak around
// the customer's firewall posture.
type brokerDialer struct {
	relay  AgentRelay
	direct TargetDialer
}

// NewBrokerDialer wraps a direct dialer with broker routing. When relay is nil
// it degrades to direct-only (and a "via agent" target then fails closed,
// because there is no relay to broker through).
func NewBrokerDialer(relay AgentRelay, timeout time.Duration) TargetDialer {
	return brokerDialer{relay: relay, direct: NewDirectDialer(timeout)}
}

func (b brokerDialer) DialTarget(ctx context.Context, target *models.PAMTarget) (net.Conn, error) {
	if target.ViaAgentID == nil {
		return b.direct.DialTarget(ctx, target)
	}
	if b.relay == nil {
		return nil, fmt.Errorf("gateway: target %s is via-agent but no relay is configured", target.Address)
	}
	conn, err := b.relay.DialThroughAgentAs(ctx, target.WorkspaceID, target.Address, "pam-gateway")
	if err != nil {
		return nil, fmt.Errorf("gateway: broker dial %s via agent: %w", target.Address, err)
	}
	return conn, nil
}

// resolveDialer returns the configured dialer or a direct one as the default,
// so a proxy constructed without a dialer behaves exactly as before.
func resolveDialer(d TargetDialer, timeout time.Duration) TargetDialer {
	if d != nil {
		return d
	}
	return NewDirectDialer(timeout)
}
