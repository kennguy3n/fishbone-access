package gateway

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// capturingRelay records the routing arguments so tests can assert the gateway
// dials strictly through the agent a target is bound to.
type capturingRelay struct {
	gotWorkspace uuid.UUID
	gotAgent     uuid.UUID
	gotAddr      string
	conn         net.Conn
	err          error
}

func (c *capturingRelay) DialThroughAgentAs(_ context.Context, workspaceID, agentID uuid.UUID, targetAddr, _ string) (net.Conn, error) {
	c.gotWorkspace = workspaceID
	c.gotAgent = agentID
	c.gotAddr = targetAddr
	return c.conn, c.err
}

// TestBrokerDialerRoutesToBoundAgent proves a via-agent target is brokered
// strictly through its ViaAgentID — not "some agent that can reach the
// address" — so a binding is an authoritative routing directive.
func TestBrokerDialerRoutesToBoundAgent(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	rel := &capturingRelay{conn: server}
	d := NewBrokerDialer(rel, time.Second)

	ws := uuid.New()
	agent := uuid.New()
	target := &models.PAMTarget{WorkspaceID: ws, Address: "10.9.9.9:5432", ViaAgentID: &agent}
	conn, err := d.DialTarget(context.Background(), target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if rel.gotAgent != agent {
		t.Fatalf("routed to agent %s, want bound agent %s", rel.gotAgent, agent)
	}
	if rel.gotWorkspace != ws || rel.gotAddr != "10.9.9.9:5432" {
		t.Fatalf("unexpected routing ws=%s addr=%s", rel.gotWorkspace, rel.gotAddr)
	}
}

// TestBrokerDialerFailsClosedWithoutRelay proves a via-agent target is never
// silently dialed directly when no relay is configured.
func TestBrokerDialerFailsClosedWithoutRelay(t *testing.T) {
	d := NewBrokerDialer(nil, time.Second)
	agent := uuid.New()
	target := &models.PAMTarget{WorkspaceID: uuid.New(), Address: "10.9.9.9:5432", ViaAgentID: &agent}
	if _, err := d.DialTarget(context.Background(), target); err == nil {
		t.Fatal("via-agent target dialed without a relay; want fail closed")
	}
}

// TestBrokerDialerDialsDirectWhenUnbound proves an unbound target bypasses the
// relay entirely and dials its address directly.
func TestBrokerDialerDialsDirectWhenUnbound(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		if c, aerr := ln.Accept(); aerr == nil {
			_ = c.Close()
		}
	}()
	rel := &capturingRelay{err: errors.New("relay must not be used for an unbound target")}
	d := NewBrokerDialer(rel, time.Second)
	target := &models.PAMTarget{WorkspaceID: uuid.New(), Address: ln.Addr().String()} // ViaAgentID nil
	conn, err := d.DialTarget(context.Background(), target)
	if err != nil {
		t.Fatalf("direct dial: %v", err)
	}
	_ = conn.Close()
	if rel.gotAddr != "" {
		t.Fatal("unbound target was routed through the relay")
	}
}
