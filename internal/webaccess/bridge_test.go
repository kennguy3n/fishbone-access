package webaccess

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/gateway"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// --- test fixture ---------------------------------------------------------

// testEnv wires the same real PAM services the production API uses — vault,
// connect-token broker, session manager with a live command-policy evaluator,
// and the takeover hub — over an in-memory SQLite database, so the bridge tests
// exercise genuine token redemption, session recording, command gating, and the
// audit hash chain rather than mocks.
type testEnv struct {
	db          *gorm.DB
	workspaceID uuid.UUID
	vault       *pam.Vault
	broker      *pam.Broker
	sessions    *pam.SessionManager
	hub         *gateway.SessionHub
	store       *memReplayStore
	bridge      *Bridge
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("auto-migrate: %v", err)
	}
	ws := &models.Workspace{Name: "tenant-web", IAMCoreTenantID: "tenant-web", Plan: "base"}
	if err := db.Create(ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	enc, err := access.CredentialEncryptorFromKey(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatalf("encryptor: %v", err)
	}
	vault := pam.NewVault(db, enc, nil)
	broker := pam.NewBroker(db, vault, nil)
	evaluator := pam.NewCommandPolicyEvaluator(db, time.Millisecond)
	hub := gateway.NewSessionHub()
	sessions := pam.NewSessionManager(db, evaluator, hub)
	store := &memReplayStore{put: map[string][]byte{}}
	bridge, err := NewBridge(BridgeConfig{
		Broker:      broker,
		Sessions:    sessions,
		Hub:         hub,
		Store:       store,
		DialTimeout: 5 * time.Second,
		// Idle timeout off by default so tests drive teardown explicitly.
	})
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}
	return &testEnv{db: db, workspaceID: ws.ID, vault: vault, broker: broker, sessions: sessions, hub: hub, store: store, bridge: bridge}
}

func (e *testEnv) createTarget(t *testing.T, protocol, address string, secret pam.Secret) *models.PAMTarget {
	t.Helper()
	target, err := e.vault.CreateTarget(context.Background(), pam.CreateTargetInput{
		WorkspaceID: e.workspaceID,
		Name:        "tgt-" + protocol,
		Protocol:    protocol,
		Address:     address,
		Username:    secret.Username,
		Secret:      secret,
		Actor:       "admin",
	})
	if err != nil {
		t.Fatalf("CreateTarget(%s): %v", protocol, err)
	}
	return target
}

func (e *testEnv) mintToken(t *testing.T, targetID uuid.UUID, subject string) string {
	t.Helper()
	raw, _, err := e.broker.MintConnectToken(context.Background(), pam.MintInput{
		WorkspaceID: e.workspaceID,
		TargetID:    targetID,
		Subject:     subject,
		Actor:       "admin",
	})
	if err != nil {
		t.Fatalf("MintConnectToken: %v", err)
	}
	return raw
}

func (e *testEnv) seedDeny(t *testing.T, name string, subjects, resources []string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"action": "deny", "subjects": subjects, "resources": resources})
	p := &models.Policy{WorkspaceID: e.workspaceID, Name: name, State: "active", Definition: datatypes.JSON(body)}
	if err := e.db.Create(p).Error; err != nil {
		t.Fatalf("seed deny: %v", err)
	}
}

func (e *testEnv) sessionRows(t *testing.T) []models.PAMSession {
	t.Helper()
	var rows []models.PAMSession
	if err := e.db.Where("workspace_id = ?", e.workspaceID).Order("started_at desc").Find(&rows).Error; err != nil {
		t.Fatalf("load sessions: %v", err)
	}
	return rows
}

func (e *testEnv) commandRows(t *testing.T, sessionID uuid.UUID) []models.PAMSessionCommand {
	t.Helper()
	var rows []models.PAMSessionCommand
	if err := e.db.Where("session_id = ?", sessionID).Order("seq asc").Find(&rows).Error; err != nil {
		t.Fatalf("load commands: %v", err)
	}
	return rows
}

// --- in-memory replay store ----------------------------------------------

type memReplayStore struct {
	mu  sync.Mutex
	put map[string][]byte
}

func (s *memReplayStore) PutReplay(_ context.Context, sessionID string, r io.Reader) error {
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, r); err != nil {
		return err
	}
	s.mu.Lock()
	s.put[sessionID] = buf.Bytes()
	s.mu.Unlock()
	return nil
}

func (s *memReplayStore) stored(sessionID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.put[sessionID]
	return ok
}

// --- fake websocket connection -------------------------------------------

type wsFrame struct {
	mt   int
	data []byte
}

// fakeConn is an in-memory wsConn: inbound frames are queued by the test and
// returned by ReadMessage in order; outbound frames are captured for assertion.
// Close unblocks any pending read with io.EOF (modelling a client disconnect).
type fakeConn struct {
	in     chan wsFrame
	mu     sync.Mutex
	out    []wsFrame
	closed chan struct{}
	once   sync.Once
}

func newFakeConn() *fakeConn {
	return &fakeConn{in: make(chan wsFrame, 64), closed: make(chan struct{})}
}

func (c *fakeConn) push(mt int, data []byte) { c.in <- wsFrame{mt, data} }

func (c *fakeConn) pushJSON(v any) {
	b, _ := json.Marshal(v)
	c.push(textMT, b)
}

func (c *fakeConn) ReadMessage() (int, []byte, error) {
	select {
	case f := <-c.in:
		return f.mt, f.data, nil
	case <-c.closed:
		return 0, nil, io.EOF
	}
}

func (c *fakeConn) WriteMessage(mt int, data []byte) error {
	select {
	case <-c.closed:
		return io.ErrClosedPipe
	default:
	}
	c.mu.Lock()
	c.out = append(c.out, wsFrame{mt, append([]byte(nil), data...)})
	c.mu.Unlock()
	return nil
}

func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }
func (c *fakeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeConn) frames() []wsFrame {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]wsFrame(nil), c.out...)
}

// textFrames decodes every captured text frame into a generic map.
func (c *fakeConn) textFrames() []map[string]any {
	var out []map[string]any
	for _, f := range c.frames() {
		if f.mt != textMT {
			continue
		}
		var m map[string]any
		if json.Unmarshal(f.data, &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

// waitFor polls the captured text frames until pred matches one, or fails.
func (c *fakeConn) waitFor(t *testing.T, what string, pred func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, m := range c.textFrames() {
			if pred(m) {
				return m
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s; frames=%v", what, c.textFrames())
	return nil
}

// gorilla websocket frame types (1 == TextMessage, 2 == BinaryMessage),
// hard-coded here so the test double need not import gorilla.
const (
	textMT   = 1
	binaryMT = 2
)

// --- tests ----------------------------------------------------------------

func TestServeRejectsInvalidToken(t *testing.T) {
	e := newTestEnv(t)
	conn := newFakeConn()
	conn.pushJSON(clientMessage{Type: msgHello, Token: "not-a-real-token"})
	done := make(chan struct{})
	go func() {
		e.bridge.ServeSSH(context.Background(), conn, ServeParams{WorkspaceID: e.workspaceID})
		close(done)
	}()

	conn.waitFor(t, "invalid-token error", func(m map[string]any) bool {
		return m["type"] == msgError && m["message"] == "invalid or expired connect token"
	})
	conn.Close()
	<-done
	if rows := e.sessionRows(t); len(rows) != 0 {
		t.Fatalf("a rejected token must not open a session, got %d", len(rows))
	}
}

func TestServeRejectsForeignWorkspace(t *testing.T) {
	e := newTestEnv(t)
	target := e.createTarget(t, models.PAMProtocolSSH, "127.0.0.1:22", pam.Secret{Username: "ops", Password: "pw"})
	token := e.mintToken(t, target.ID, "alice")
	conn := newFakeConn()
	conn.pushJSON(clientMessage{Type: msgHello, Token: token})

	done := make(chan struct{})
	// Caller authenticated for a DIFFERENT workspace than the token's.
	go func() {
		e.bridge.ServeSSH(context.Background(), conn, ServeParams{WorkspaceID: uuid.New()})
		close(done)
	}()
	conn.waitFor(t, "workspace mismatch error", func(m map[string]any) bool {
		return m["type"] == msgError && m["message"] == "connect token does not belong to this workspace"
	})
	conn.Close()
	<-done
	// The just-opened session must be reconciled closed, not left active.
	for _, s := range e.sessionRows(t) {
		if s.State == "active" {
			t.Fatalf("session %s left active after workspace rejection", s.ID)
		}
	}
}

func TestServeRejectsProtocolMismatch(t *testing.T) {
	e := newTestEnv(t)
	// A Postgres token driven on the SSH terminal endpoint must be refused.
	target := e.createTarget(t, models.PAMProtocolPostgres, "127.0.0.1:5432", pam.Secret{Username: "pg", Password: "pw"})
	token := e.mintToken(t, target.ID, "alice")
	conn := newFakeConn()
	conn.pushJSON(clientMessage{Type: msgHello, Token: token})

	done := make(chan struct{})
	go func() {
		e.bridge.ServeSSH(context.Background(), conn, ServeParams{WorkspaceID: e.workspaceID})
		close(done)
	}()
	conn.waitFor(t, "protocol mismatch error", func(m map[string]any) bool {
		return m["type"] == msgError && m["message"] == "connect token is not for this access type"
	})
	conn.Close()
	<-done
	for _, s := range e.sessionRows(t) {
		if s.State == "active" {
			t.Fatalf("session %s left active after protocol rejection", s.ID)
		}
	}
}

func TestServeSSHEndToEnd(t *testing.T) {
	e := newTestEnv(t)
	addr, cleanup := startEchoSSHServer(t)
	defer cleanup()

	target := e.createTarget(t, models.PAMProtocolSSH, addr, pam.Secret{Username: "ops", Password: "pw"})
	token := e.mintToken(t, target.ID, "alice")

	conn := newFakeConn()
	conn.pushJSON(clientMessage{Type: msgHello, Token: token, Cols: 100, Rows: 30})

	done := make(chan struct{})
	go func() {
		e.bridge.ServeSSH(context.Background(), conn, ServeParams{WorkspaceID: e.workspaceID})
		close(done)
	}()

	ready := conn.waitFor(t, "ready frame", func(m map[string]any) bool { return m["type"] == msgReady })
	if ready["protocol"] != models.PAMProtocolSSH || ready["recording"] != true || ready["policy_governed"] != true {
		t.Fatalf("ready frame missing governance flags: %v", ready)
	}
	sessionID := ready["session_id"].(string)

	// Type a command; the echo server reflects it back as terminal output.
	conn.push(binaryMT, []byte("whoami\n"))

	if !waitForBinary(conn, []byte("whoami"), 3*time.Second) {
		t.Fatalf("did not receive echoed terminal output; frames=%v", conn.frames())
	}

	conn.Close()
	<-done

	// Session row closed, recording persisted, command logged, recording
	// evidence pinned on the session.
	var sess models.PAMSession
	if err := e.db.Where("id = ?", sessionID).First(&sess).Error; err != nil {
		t.Fatalf("load session: %v", err)
	}
	if sess.State == "active" {
		t.Fatalf("session left active after disconnect")
	}
	if !e.store.stored(sessionID) {
		t.Fatalf("recording was not flushed to the replay store")
	}
	cmds := e.commandRows(t, sess.ID)
	if len(cmds) == 0 {
		t.Fatalf("expected the typed command to be logged")
	}
	if cmds[0].Command != "whoami" {
		t.Fatalf("logged command = %q, want whoami", cmds[0].Command)
	}
}

func TestServeSSHHeartbeat(t *testing.T) {
	e := newTestEnv(t)
	addr, cleanup := startEchoSSHServer(t)
	defer cleanup()

	target := e.createTarget(t, models.PAMProtocolSSH, addr, pam.Secret{Username: "ops", Password: "pw"})
	token := e.mintToken(t, target.ID, "alice")

	conn := newFakeConn()
	conn.pushJSON(clientMessage{Type: msgHello, Token: token})
	done := make(chan struct{})
	go func() {
		e.bridge.ServeSSH(context.Background(), conn, ServeParams{WorkspaceID: e.workspaceID})
		close(done)
	}()

	conn.waitFor(t, "ready frame", func(m map[string]any) bool { return m["type"] == msgReady })

	// A heartbeat must be answered with a pong echoing the same timestamp, so
	// the UI can derive a live round-trip latency reading.
	conn.pushJSON(clientMessage{Type: msgPing, TS: 1234567})
	pong := conn.waitFor(t, "pong frame", func(m map[string]any) bool { return m["type"] == msgPong })
	if pong["ts"] != float64(1234567) {
		t.Fatalf("pong echoed ts = %v, want 1234567", pong["ts"])
	}

	conn.Close()
	<-done
}

func TestServeSSHPolicyDenyTearsDown(t *testing.T) {
	e := newTestEnv(t)
	e.seedDeny(t, "deny-all", []string{"*"}, []string{"cmd:*"})
	addr, cleanup := startEchoSSHServer(t)
	defer cleanup()

	target := e.createTarget(t, models.PAMProtocolSSH, addr, pam.Secret{Username: "ops", Password: "pw"})
	token := e.mintToken(t, target.ID, "alice")

	conn := newFakeConn()
	conn.pushJSON(clientMessage{Type: msgHello, Token: token})
	done := make(chan struct{})
	go func() {
		e.bridge.ServeSSH(context.Background(), conn, ServeParams{WorkspaceID: e.workspaceID})
		close(done)
	}()

	conn.waitFor(t, "ready frame", func(m map[string]any) bool { return m["type"] == msgReady })
	conn.push(binaryMT, []byte("rm -rf /\n"))

	status := conn.waitFor(t, "terminated status", func(m map[string]any) bool {
		return m["type"] == msgStatus && m["state"] == stateTerminated
	})
	if status["reason"] == "" {
		t.Fatalf("terminated status should carry a reason")
	}
	conn.Close()
	<-done

	rows := e.sessionRows(t)
	if len(rows) != 1 {
		t.Fatalf("want 1 session, got %d", len(rows))
	}
	cmds := e.commandRows(t, rows[0].ID)
	if len(cmds) == 0 || cmds[0].Decision != models.PAMDecisionDeny {
		t.Fatalf("denied command not logged as deny: %+v", cmds)
	}
}

func TestRunStatementGatesAndStreams(t *testing.T) {
	e := newTestEnv(t)
	target := e.createTarget(t, models.PAMProtocolPostgres, "127.0.0.1:5432", pam.Secret{Username: "pg", Password: "pw"})
	token := e.mintToken(t, target.ID, "alice")
	leased, err := e.broker.RedeemConnectToken(context.Background(), token, "127.0.0.1")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	defer func() { _ = e.sessions.CloseSession(context.Background(), e.workspaceID, leased.Session.ID) }()

	conn := newFakeConn()
	sender := newWSSender(conn, time.Second)
	rec := gateway.NewIORecorder(context.Background(), leased.Session.ID.String(), 0)
	console := &fakeConsole{result: resultMessage{Type: msgResult, Columns: []queryColumn{{Name: "n"}}, Rows: [][]*string{{strptr("1")}}}}

	// Allowed statement → result frame + console executed + command logged.
	e.bridge.runStatement(context.Background(), console, sender, leased.Session, rec, "SELECT 1")
	res := conn.waitFor(t, "result frame", func(m map[string]any) bool { return m["type"] == msgResult })
	if cols, _ := res["columns"].([]any); len(cols) != 1 {
		t.Fatalf("result frame missing columns: %v", res)
	}
	if console.calls != 1 {
		t.Fatalf("console.run should have been called once, got %d", console.calls)
	}

	// Now deny everything and confirm the next statement is refused WITHOUT
	// reaching the upstream, surfaced as a denied error.
	e.seedDeny(t, "deny-all", []string{"*"}, []string{"cmd:*"})
	time.Sleep(5 * time.Millisecond) // policy cache TTL is 1ms
	e.bridge.runStatement(context.Background(), console, sender, leased.Session, rec, "DROP TABLE users")
	denied := conn.waitFor(t, "denied error", func(m map[string]any) bool {
		return m["type"] == msgError && m["denied"] == true
	})
	if denied["message"] == "" {
		t.Fatalf("denied error must carry a reason")
	}
	if console.calls != 1 {
		t.Fatalf("denied statement must not reach the upstream (calls=%d)", console.calls)
	}
}

func strptr(s string) *string { return &s }

// fakeConsole is a dbConsole double for the gating test (a real Postgres is not
// available in unit tests; the DB protocol loop's policy gate and result
// streaming are what is under test here, not the pgx wire protocol).
type fakeConsole struct {
	result resultMessage
	calls  int
}

func (f *fakeConsole) run(context.Context, string) (resultMessage, error) {
	f.calls++
	return f.result, nil
}
func (f *fakeConsole) close() {}

// fakeLeaseLookup is a LeaseExpiryLookup double for the lease-countdown test.
type fakeLeaseLookup struct {
	lease *models.PAMLease
	err   error
}

func (f *fakeLeaseLookup) GetLease(context.Context, uuid.UUID, uuid.UUID) (*models.PAMLease, error) {
	return f.lease, f.err
}

// TestLeaseExpiry covers populating the UI lease-countdown field: a live lease
// yields its RFC3339 expiry, while every degraded path (no lookup wired, a
// direct-mint session with no lease, a lookup error, or a lease with no expiry)
// yields an empty string so an otherwise-governed session still opens.
func TestLeaseExpiry(t *testing.T) {
	exp := time.Date(2031, 6, 15, 12, 0, 0, 0, time.UTC)
	leaseID := uuid.New()
	ws := uuid.New()
	withLease := &models.PAMSession{WorkspaceID: ws, LeaseID: &leaseID}

	cases := []struct {
		name    string
		lookup  LeaseExpiryLookup
		session *models.PAMSession
		want    string
	}{
		{"live lease populates RFC3339 expiry", &fakeLeaseLookup{lease: &models.PAMLease{ExpiresAt: &exp}}, withLease, exp.Format(time.RFC3339)},
		{"no lookup wired", nil, withLease, ""},
		{"direct-mint session has no lease", &fakeLeaseLookup{lease: &models.PAMLease{ExpiresAt: &exp}}, &models.PAMSession{WorkspaceID: ws}, ""},
		{"lookup error must not block the session", &fakeLeaseLookup{err: errors.New("db down")}, withLease, ""},
		{"lease without expiry", &fakeLeaseLookup{lease: &models.PAMLease{}}, withLease, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &Bridge{leases: tc.lookup}
			if got := b.leaseExpiry(context.Background(), tc.session); got != tc.want {
				t.Fatalf("leaseExpiry = %q, want %q", got, tc.want)
			}
		})
	}
}

// --- in-process SSH upstream ----------------------------------------------

// startEchoSSHServer stands up a real SSH server on a loopback port that
// accepts any password, grants pty-req/shell, and echoes channel input back as
// output. It is a genuine SSH endpoint (real handshake, channels, requests), so
// the bridge's upstream dial, PTY request, and byte plumbing are exercised
// end-to-end; only the "shell" is a trivial echo.
func startEchoSSHServer(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("gen host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveEchoSSH(c, cfg)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func serveEchoSSH(c net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sc.Close() }()
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			return
		}
		go func() {
			for req := range chReqs {
				switch req.Type {
				case "pty-req", "shell", "window-change", "env":
					_ = req.Reply(true, nil)
				default:
					_ = req.Reply(false, nil)
				}
			}
		}()
		go func() {
			_, _ = io.Copy(ch, ch)
			_ = ch.Close()
		}()
	}
}

// waitForBinary polls captured frames for a binary frame containing want.
func waitForBinary(c *fakeConn, want []byte, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, f := range c.frames() {
			if f.mt == binaryMT && bytes.Contains(f.data, want) {
				return true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
