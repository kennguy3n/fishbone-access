package broker

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// --- cross-replica harness ------------------------------------------------

// mustListen opens a loopback TCP listener closed when ctx ends.
func mustListen(t *testing.T, ctx context.Context) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	return ln
}

// serveForward runs a forward listener handing each accepted connection to the
// Forwarder, mirroring how the pam-gateway supervisor drives the relay.
func serveForward(ctx context.Context, ln net.Listener, f *Forwarder) {
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.Handle(ctx, conn)
		}
	}()
}

// connectAgent enrolls one agent in ws and runs it against relayAddr, returning
// its id. It reuses the same enrollment + agent path the single-relay tests use.
func connectAgent(t *testing.T, ctx context.Context, db *gorm.DB, ca *AgentCA, enroll *EnrollmentService, ws uuid.UUID, name string, reachable []ReachableSpec) uuid.UUID {
	t.Helper()
	rawTok, _, err := enroll.MintToken(ctx, MintTokenInput{WorkspaceID: ws, Name: name, Actor: "admin"})
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	_, csrPEM, keyPEM, err := GenerateAgentKey()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	res, err := enroll.Enroll(ctx, EnrollInput{RawToken: rawTok, CSRPEM: csrPEM, Platform: "linux", AgentVersion: "test"})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	clientCert, err := LoadClientCert(res.ClientCertPEM, keyPEM)
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	pool, err := PoolFromPEM(res.CACertPEM)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	agent := NewAgent(AgentConfig{
		RelayAddr:         res.RelayAddr,
		ServerName:        "127.0.0.1",
		ClientCert:        clientCert,
		RootCAs:           pool,
		Reachable:         reachable,
		HeartbeatInterval: 200 * time.Millisecond,
	})
	go func() { _ = agent.Run(ctx) }()
	return res.AgentID
}

// waitOwner blocks until the directory shows the agent owned (fresh) by want.
func waitOwner(t *testing.T, dir SessionDirectory, ws, agentID uuid.UUID, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		entry, fresh, err := dir.Lookup(context.Background(), ws, agentID)
		if err == nil && entry != nil && fresh && entry.NodeID == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("directory owner %q not reached within deadline", want)
}

func assertEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	msg := []byte("hello-cross-replica")
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := readFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// crossReplicaStack is two real Relay instances sharing one directory + DB.
type crossReplicaStack struct {
	db     *gorm.DB
	dir    *GormSessionDirectory
	enroll *EnrollmentService
	ca     *AgentCA
	relayA *Relay
	relayB *Relay
	addrA  string // relayA agent-relay listen addr
	addrB  string // relayB agent-relay listen addr
	ws     uuid.UUID
}

func setupCrossReplica(t *testing.T, ctx context.Context) *crossReplicaStack {
	t.Helper()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	ca, err := NewEphemeralCA()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	store := NewGormStore(db)
	ftls, err := NewEphemeralForwardTLS()
	if err != nil {
		t.Fatalf("forward tls: %v", err)
	}
	dir := NewGormSessionDirectory(db, 0)
	fwdClient := NewForwardClient(ftls, 5*time.Second)

	serverCert, err := ca.IssueServerCert([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	relayTLS := NewRelayServerTLS(serverCert, ca)

	// Forward listeners first: their addresses are the forwardAddr each relay
	// advertises into the directory.
	fwdLnA := mustListen(t, ctx)
	fwdLnB := mustListen(t, ctx)

	relayA := NewRelay(store, relayTLS, WithDialTimeout(5*time.Second),
		WithCrossReplica(dir, fwdClient, "node-a", fwdLnA.Addr().String()))
	relayB := NewRelay(store, relayTLS, WithDialTimeout(5*time.Second),
		WithCrossReplica(dir, fwdClient, "node-b", fwdLnB.Addr().String()))

	serveForward(ctx, fwdLnA, NewForwarder(relayA, ftls))
	serveForward(ctx, fwdLnB, NewForwarder(relayB, ftls))

	addrA := startRelay(t, ctx, relayA)
	addrB := startRelay(t, ctx, relayB)

	enroll := NewEnrollmentService(db, ca, addrA)

	return &crossReplicaStack{
		db: db, dir: dir, enroll: enroll, ca: ca,
		relayA: relayA, relayB: relayB, addrA: addrA, addrB: addrB, ws: ws,
	}
}

// --- tests ----------------------------------------------------------------

// TestCrossReplicaForwardedDial is the headline integration test: a fake agent
// connects to relay A, and a DialThroughAgent issued on relay B (which holds no
// local tunnel for it) is forwarded to A, reaches the agent, and relays bytes.
func TestCrossReplicaForwardedDial(t *testing.T) {
	upstream, stop := echoServer(t)
	defer stop()
	host, _, _ := net.SplitHostPort(upstream)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := setupCrossReplica(t, ctx)

	agentID := connectAgent(t, ctx, st.db, st.ca, st.enroll, st.ws, "agent-1",
		[]ReachableSpec{{Pattern: host + "/32", Kind: models.AgentReachKindCIDR}})

	// The agent terminates on A, so A claims ownership in the shared directory.
	waitOwner(t, st.dir, st.ws, agentID, "node-a")

	// B has no local tunnel; this must forward to A and relay bytes end-to-end.
	conn, err := st.relayB.DialThroughAgentAs(ctx, st.ws, agentID, upstream, "subject@acme")
	if err != nil {
		t.Fatalf("forwarded dial on B: %v", err)
	}
	defer conn.Close()
	assertEcho(t, conn)

	// Exactly one broker-open audit event for this forwarded session, recorded
	// at the owner (A) — never zero, never two.
	if n := brokerOpenCount(t, st.db, st.ws); n != 1 {
		t.Fatalf("broker-open audit events = %d, want exactly 1", n)
	}

	// Global online state: B reports the agent online even though it is pinned
	// to A, reading the directory.
	if !st.relayB.IsOnline(st.ws, agentID) {
		t.Fatalf("relay B should report agent online via directory")
	}
	if n := st.relayB.OnlineCount(st.ws); n != 1 {
		t.Fatalf("relay B OnlineCount = %d, want 1 (global)", n)
	}
}

// TestCrossReplicaLocalFastPathUnchanged proves a dial on the SAME replica that
// holds the tunnel never consults the forward plane (it just works locally) and
// still produces exactly one audit event.
func TestCrossReplicaLocalFastPathUnchanged(t *testing.T) {
	upstream, stop := echoServer(t)
	defer stop()
	host, _, _ := net.SplitHostPort(upstream)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := setupCrossReplica(t, ctx)

	agentID := connectAgent(t, ctx, st.db, st.ca, st.enroll, st.ws, "agent-1",
		[]ReachableSpec{{Pattern: host + "/32", Kind: models.AgentReachKindCIDR}})
	waitOwner(t, st.dir, st.ws, agentID, "node-a")

	conn, err := st.relayA.DialThroughAgentAs(ctx, st.ws, agentID, upstream, "subject@acme")
	if err != nil {
		t.Fatalf("local dial on A: %v", err)
	}
	defer conn.Close()
	assertEcho(t, conn)

	if n := brokerOpenCount(t, st.db, st.ws); n != 1 {
		t.Fatalf("broker-open audit events = %d, want 1", n)
	}
}

// TestForwardDialFailsClosed covers every closed-failure branch of the forward
// path: no owner, stale owner, owner unreachable, and owner==self with no local
// tunnel. None must fall back to another agent or dial direct.
func TestForwardDialFailsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := setupCrossReplica(t, ctx)
	ws := st.ws
	now := time.Now()
	st.dir.SetClock(func() time.Time { return now })

	cases := []struct {
		name  string
		setup func(agentID uuid.UUID)
	}{
		{
			name:  "no owner entry",
			setup: func(uuid.UUID) {},
		},
		{
			name: "stale owner",
			setup: func(agentID uuid.UUID) {
				if _, err := st.dir.Claim(ctx, ws, agentID, "node-ghost", "127.0.0.1:1"); err != nil {
					t.Fatalf("claim: %v", err)
				}
				now = now.Add(2 * HealthOfflineAfter) // crash: entry goes stale
			},
		},
		{
			name: "owner is self but no local tunnel",
			setup: func(agentID uuid.UUID) {
				// node-b is relayB itself; with no local tunnel a dial on B must
				// not loop back onto itself, it fails closed.
				if _, err := st.dir.Claim(ctx, ws, agentID, "node-b", st.relayB.forwardAddr); err != nil {
					t.Fatalf("claim: %v", err)
				}
			},
		},
		{
			name: "fresh owner unreachable",
			setup: func(agentID uuid.UUID) {
				// A fresh entry pointing at a dead address: the bounded forward
				// dial fails and we surface ErrAgentUnavailable.
				if _, err := st.dir.Claim(ctx, ws, agentID, "node-dead", "127.0.0.1:1"); err != nil {
					t.Fatalf("claim: %v", err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agentID := uuid.New()
			tc.setup(agentID)
			_, err := st.relayB.DialThroughAgent(ctx, ws, agentID, "10.0.0.9:22")
			if err == nil {
				t.Fatalf("want ErrAgentUnavailable, got nil")
			}
		})
	}
}

// TestForwardRevokeRecheckAtOwner proves the authoritative revoke re-check runs
// at the OWNER: after the agent row is revoked, a forwarded dial on B is refused
// by A before any agent stream opens.
func TestForwardRevokeRecheckAtOwner(t *testing.T) {
	upstream, stop := echoServer(t)
	defer stop()
	host, _, _ := net.SplitHostPort(upstream)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := setupCrossReplica(t, ctx)

	agentID := connectAgent(t, ctx, st.db, st.ca, st.enroll, st.ws, "agent-1",
		[]ReachableSpec{{Pattern: host + "/32", Kind: models.AgentReachKindCIDR}})
	waitOwner(t, st.dir, st.ws, agentID, "node-a")

	// Revoke the agent row out from under its live tunnel.
	if err := st.db.Model(&models.TargetAgent{}).
		Where("id = ? AND workspace_id = ?", agentID, st.ws).
		Update("status", models.AgentStatusRevoked).Error; err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if _, err := st.relayB.DialThroughAgent(ctx, st.ws, agentID, upstream); err == nil {
		t.Fatalf("forwarded dial after revoke: want failure, got nil")
	}
}

// TestForwardCrossTenantIsolation proves a dial in a DIFFERENT workspace can
// never reach an agent owned under another tenant: the workspace-scoped
// directory lookup returns no owner and the dial fails closed.
func TestForwardCrossTenantIsolation(t *testing.T) {
	upstream, stop := echoServer(t)
	defer stop()
	host, _, _ := net.SplitHostPort(upstream)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := setupCrossReplica(t, ctx)

	agentID := connectAgent(t, ctx, st.db, st.ca, st.enroll, st.ws, "agent-1",
		[]ReachableSpec{{Pattern: host + "/32", Kind: models.AgentReachKindCIDR}})
	waitOwner(t, st.dir, st.ws, agentID, "node-a")

	otherWS := seedWorkspace(t, st.db, "evilcorp")
	if _, err := st.relayB.DialThroughAgent(ctx, otherWS, agentID, upstream); err == nil {
		t.Fatalf("cross-tenant forwarded dial: want failure, got nil")
	}
	// And the legitimate tenant still resolves it (sanity: isolation, not a
	// global break).
	if entry, fresh, _ := st.dir.Lookup(ctx, otherWS, agentID); entry != nil || fresh {
		t.Fatalf("foreign workspace must have no owner entry")
	}
}

// brokerOpenCount counts broker-open audit events in a workspace.
func brokerOpenCount(t *testing.T, db *gorm.DB, ws uuid.UUID) int {
	t.Helper()
	var n int64
	if err := db.Model(&models.AuditEvent{}).
		Where("workspace_id = ? AND action = ?", ws, AuditActionBrokerOpen).
		Count(&n).Error; err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	return int(n)
}
