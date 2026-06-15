package broker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
)

// --- harness --------------------------------------------------------------

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// A ":memory:" SQLite database is per-connection, so pin the pool to a single
	// connection: the relay, agent goroutines, and dial paths all share the one
	// migrated database rather than racing onto fresh empty ones.
	if err := database.ApplyPoolLimits(db, 1, 1, 0); err != nil {
		t.Fatalf("pool limits: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("auto-migrate: %v", err)
	}
	return db
}

func seedWorkspace(t *testing.T, db *gorm.DB, name string) uuid.UUID {
	t.Helper()
	ws := &models.Workspace{Name: name, IAMCoreTenantID: name, Plan: "base"}
	if err := db.Create(ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	return ws.ID
}

// echoServer is a fake private upstream the agent reaches; it echoes bytes back.
func echoServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	var wg sync.WaitGroup
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close(); wg.Wait() }
}

// startRelay spins a real TCP relay listener handing connections to r.Handle.
func startRelay(t *testing.T, ctx context.Context, r *Relay) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go r.Handle(ctx, conn)
		}
	}()
	return ln.Addr().String()
}

// fullStack wires CA, enrollment, store, relay, and one enrolled+connected agent
// reachable for the given specs. It returns the relay and the agent id.
type fullStack struct {
	db        *gorm.DB
	ca        *AgentCA
	enroll    *EnrollmentService
	relay     *Relay
	store     *GormStore
	workspace uuid.UUID
	agentID   uuid.UUID
}

func setupStack(t *testing.T, reachable []ReachableSpec) (context.Context, *fullStack) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	ca, err := NewEphemeralCA()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	store := NewGormStore(db)
	serverCert, err := ca.IssueServerCert([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	relay := NewRelay(store, NewRelayServerTLS(serverCert, ca), WithDialTimeout(5*time.Second))
	relayAddr := startRelay(t, ctx, relay)

	enroll := NewEnrollmentService(db, ca, relayAddr)
	rawTok, _, err := enroll.MintToken(ctx, MintTokenInput{WorkspaceID: ws, Name: "agent-1", Actor: "admin"})
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

	waitOnline(t, relay, ws, res.AgentID, true)

	return ctx, &fullStack{db: db, ca: ca, enroll: enroll, relay: relay, store: store, workspace: ws, agentID: res.AgentID}
}

func waitOnline(t *testing.T, r *Relay, ws, agentID uuid.UUID, want bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if r.IsOnline(ws, agentID) == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("agent online=%v not reached within deadline", want)
}

// --- tests ----------------------------------------------------------------

func TestEnrollTokenIsOneShot(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	ca, _ := NewEphemeralCA()
	enroll := NewEnrollmentService(db, ca, "relay:7443")

	raw, _, err := enroll.MintToken(ctx, MintTokenInput{WorkspaceID: ws, Name: "a", Actor: "admin"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	_, csr, _, _ := GenerateAgentKey()
	if _, err := enroll.Enroll(ctx, EnrollInput{RawToken: raw, CSRPEM: csr}); err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	_, csr2, _, _ := GenerateAgentKey()
	if _, err := enroll.Enroll(ctx, EnrollInput{RawToken: raw, CSRPEM: csr2}); !errors.Is(err, ErrEnrollment) {
		t.Fatalf("replay enroll: want ErrEnrollment, got %v", err)
	}
}

func TestEnrollRejectsExpiredToken(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	ca, _ := NewEphemeralCA()
	now := time.Now()
	enroll := NewEnrollmentService(db, ca, "relay:7443")
	enroll.SetClock(func() time.Time { return now })
	enroll.SetTokenTTL(time.Minute)

	raw, _, err := enroll.MintToken(ctx, MintTokenInput{WorkspaceID: ws, Name: "a", Actor: "admin"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	now = now.Add(2 * time.Minute) // token now expired
	_, csr, _, _ := GenerateAgentKey()
	if _, err := enroll.Enroll(ctx, EnrollInput{RawToken: raw, CSRPEM: csr}); !errors.Is(err, ErrEnrollment) {
		t.Fatalf("expired enroll: want ErrEnrollment, got %v", err)
	}
}

func TestDialThroughAgentEndToEnd(t *testing.T) {
	upstream, stop := echoServer(t)
	defer stop()
	host, _, _ := net.SplitHostPort(upstream)

	ctx, st := setupStack(t, []ReachableSpec{{Pattern: host + "/32", Kind: models.AgentReachKindCIDR}})

	// Open several concurrent brokered streams to exercise multiplexing.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := st.relay.DialThroughAgent(ctx, st.workspace, upstream)
			if err != nil {
				t.Errorf("dial through agent: %v", err)
				return
			}
			defer conn.Close()
			msg := []byte("hello-tunnel")
			if _, err := conn.Write(msg); err != nil {
				t.Errorf("write: %v", err)
				return
			}
			buf := make([]byte, len(msg))
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Errorf("read echo: %v", err)
				return
			}
			if !bytes.Equal(buf, msg) {
				t.Errorf("echo mismatch: got %q", buf)
			}
		}()
	}
	wg.Wait()
}

func TestDialFailsForUnreachableTarget(t *testing.T) {
	ctx, st := setupStack(t, []ReachableSpec{{Pattern: "10.0.0.0/24", Kind: models.AgentReachKindCIDR}})
	_, err := st.relay.DialThroughAgent(ctx, st.workspace, "192.168.5.5:22")
	if !errors.Is(err, ErrAgentUnavailable) {
		t.Fatalf("want ErrAgentUnavailable, got %v", err)
	}
}

func TestCrossTenantBrokeringIsImpossible(t *testing.T) {
	upstream, stop := echoServer(t)
	defer stop()
	host, _, _ := net.SplitHostPort(upstream)
	ctx, st := setupStack(t, []ReachableSpec{{Pattern: host + "/32", Kind: models.AgentReachKindCIDR}})

	otherWS := seedWorkspace(t, st.db, "evil-corp")
	_, err := st.relay.DialThroughAgent(ctx, otherWS, upstream)
	if !errors.Is(err, ErrAgentUnavailable) {
		t.Fatalf("cross-tenant dial: want ErrAgentUnavailable, got %v", err)
	}
}

func TestRevokedAgentCannotBroker(t *testing.T) {
	upstream, stop := echoServer(t)
	defer stop()
	host, _, _ := net.SplitHostPort(upstream)
	ctx, st := setupStack(t, []ReachableSpec{{Pattern: host + "/32", Kind: models.AgentReachKindCIDR}})

	if err := st.enroll.Revoke(ctx, st.workspace, st.agentID, "admin"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := st.relay.DialThroughAgent(ctx, st.workspace, upstream); err == nil {
		t.Fatal("revoked agent brokered a session")
	}
}

// TestOperatorBindingReachability proves the operator-binding source of reach:
// a PAM target bound to an agent (via_agent_id) becomes an exact host spec the
// relay will broker to, without widening reach to any other address and without
// duplicating the agent's self-reported specs.
func TestOperatorBindingReachability(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	store := NewGormStore(db)

	agentID := uuid.New()
	other := uuid.New()
	for _, a := range []uuid.UUID{agentID, other} {
		if err := db.Create(&models.TargetAgent{
			Base: models.Base{ID: a}, WorkspaceID: ws, Name: "agent-" + a.String()[:8],
			CertFingerprint: "fp-" + a.String(), CertSerial: "1",
			CertNotAfter: time.Now().Add(time.Hour), Status: models.AgentStatusOnline,
		}).Error; err != nil {
			t.Fatalf("seed agent: %v", err)
		}
	}
	// A target bound to agentID at an address no self-reported spec covers, and
	// one bound to a different agent that must NOT leak into agentID's reach.
	mustCreateTarget(t, db, ws, "db", models.PAMProtocolPostgres, "10.9.9.9:5432", &agentID)
	mustCreateTarget(t, db, ws, "cache", models.PAMProtocolRedis, "10.9.9.10:6379", &other)

	specs, err := store.OperatorBindings(ctx, ws, agentID)
	if err != nil {
		t.Fatalf("operator bindings: %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("want exactly one operator binding, got %d: %+v", len(specs), specs)
	}
	rs := newReachableSet(specs)
	if !rs.allows("10.9.9.9:5432") {
		t.Fatal("operator-bound target should be reachable")
	}
	if rs.allows("10.9.9.10:6379") {
		t.Fatal("a target bound to a different agent must not be reachable")
	}
	if rs.allows("10.9.9.9:22") {
		t.Fatal("binding must not widen reach to other ports on the same host")
	}
}

// TestBindTargetRejectsUnbrokerableProtocol fails closed when a target's
// protocol has no dialer-wired proxy, so binding can never silently bypass the
// tunnel by dialing the upstream directly.
func TestBindTargetRejectsUnbrokerableProtocol(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	dir := NewAgentDirectory(db)

	agentID := uuid.New()
	if err := db.Create(&models.TargetAgent{
		Base: models.Base{ID: agentID}, WorkspaceID: ws, Name: "a1",
		CertFingerprint: "fp", CertSerial: "1",
		CertNotAfter: time.Now().Add(time.Hour), Status: models.AgentStatusOnline,
	}).Error; err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	// A row written directly with an unsupported protocol (bypassing the vault's
	// CRUD validation) to exercise the bind-time allow-list.
	tgt := mustCreateTarget(t, db, ws, "weird", "telnet", "10.0.0.5:23", nil)

	if err := dir.BindTarget(ctx, ws, agentID, tgt.ID, "admin"); !errors.Is(err, ErrValidation) {
		t.Fatalf("bind unbrokerable protocol: want ErrValidation, got %v", err)
	}
	var reloaded models.PAMTarget
	if err := db.Where("id = ?", tgt.ID).Take(&reloaded).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.ViaAgentID != nil {
		t.Fatalf("target must not be bound when protocol is rejected, via=%v", reloaded.ViaAgentID)
	}
}

func mustCreateTarget(t *testing.T, db *gorm.DB, ws uuid.UUID, name, proto, addr string, via *uuid.UUID) *models.PAMTarget {
	t.Helper()
	tgt := &models.PAMTarget{
		Base: models.Base{ID: uuid.New()}, WorkspaceID: ws, Name: name,
		Protocol: proto, Address: addr, ViaAgentID: via,
	}
	if err := db.Create(tgt).Error; err != nil {
		t.Fatalf("seed target %q: %v", name, err)
	}
	return tgt
}

func TestAuthorizeConnectRejectsRevoked(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	store := NewGormStore(db)
	agentID := uuid.New()
	if err := db.Create(&models.TargetAgent{
		Base:            models.Base{ID: agentID},
		WorkspaceID:     ws,
		Name:            "a",
		CertFingerprint: "fp",
		CertSerial:      "1",
		CertNotAfter:    time.Now().Add(time.Hour),
		Status:          models.AgentStatusRevoked,
	}).Error; err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	_, err := store.AuthorizeConnect(ctx, AgentIdentity{AgentID: agentID, WorkspaceID: ws, Fingerprint: "fp"})
	if err == nil {
		t.Fatal("authorize connect allowed a revoked agent")
	}
}
