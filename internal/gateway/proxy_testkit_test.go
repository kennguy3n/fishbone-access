package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// proxyTestEnv is the shared fixture for the protocol-proxy integration tests
// (Redis, MongoDB, MSSQL, RDP, VNC, HTTP). It wires the same real PAM services
// the production gateway uses — vault, connect-token broker, session manager
// with a live command-policy evaluator, and the takeover hub — over an
// in-memory SQLite database, so a test exercises genuine token redemption,
// vault credential injection, session recording, and the audit hash chain
// rather than mocks of those subsystems. Only the upstream server itself is a
// test double (a real RDP/VNC/Mongo/MSSQL server is impractical in a unit
// test), and each such double is documented at its use site.
type proxyTestEnv struct {
	db          *gorm.DB
	workspaceID uuid.UUID
	vault       *pam.Vault
	broker      *pam.Broker
	sessions    *pam.SessionManager
	hub         *SessionHub
	store       *memStore
}

// newProxyTestEnv builds the fixture. The command-policy evaluator uses a tiny
// TTL so a deny policy seeded mid-test takes effect immediately.
func newProxyTestEnv(t *testing.T) *proxyTestEnv {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("auto-migrate: %v", err)
	}
	ws := &models.Workspace{Name: "tenant-proxy", IAMCoreTenantID: "tenant-proxy", Plan: "base"}
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
	sessions := pam.NewSessionManager(db, evaluator, nil)
	return &proxyTestEnv{
		db:          db,
		workspaceID: ws.ID,
		vault:       vault,
		broker:      broker,
		sessions:    sessions,
		hub:         NewSessionHub(),
		store:       &memStore{put: map[string][]byte{}},
	}
}

// createTarget seals a target with the given protocol/address/secret.
func (e *proxyTestEnv) createTarget(t *testing.T, protocol, address string, secret pam.Secret) *models.PAMTarget {
	t.Helper()
	target, err := e.vault.CreateTarget(context.Background(), pam.CreateTargetInput{
		WorkspaceID: e.workspaceID,
		Name:        "tgt-" + protocol + "-" + uuid.NewString()[:8],
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

// mintToken mints a one-shot connect token for the target.
func (e *proxyTestEnv) mintToken(t *testing.T, targetID uuid.UUID, subject string) string {
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

// seedDeny installs an active deny policy whose command-plane resource patterns
// gate the named subjects (use []string{"*"} for all).
func (e *proxyTestEnv) seedDeny(t *testing.T, name string, subjects, resources []string) {
	t.Helper()
	body := mustMarshal(t, map[string]any{
		"action":    "deny",
		"subjects":  subjects,
		"resources": resources,
	})
	p := &models.Policy{WorkspaceID: e.workspaceID, Name: name, State: "active", Definition: datatypes.JSON(body)}
	if err := e.db.Create(p).Error; err != nil {
		t.Fatalf("seed deny policy: %v", err)
	}
}

// sessionRows returns every session row for the workspace, newest first.
func (e *proxyTestEnv) sessionRows(t *testing.T) []models.PAMSession {
	t.Helper()
	var rows []models.PAMSession
	if err := e.db.Where("workspace_id = ?", e.workspaceID).Order("started_at desc").Find(&rows).Error; err != nil {
		t.Fatalf("load sessions: %v", err)
	}
	return rows
}

// commandRows returns the logged command rows for a session, in seq order.
func (e *proxyTestEnv) commandRows(t *testing.T, sessionID uuid.UUID) []models.PAMSessionCommand {
	t.Helper()
	var rows []models.PAMSessionCommand
	if err := e.db.Where("session_id = ?", sessionID).Order("seq asc").Find(&rows).Error; err != nil {
		t.Fatalf("load commands: %v", err)
	}
	return rows
}

// pipeConn returns a connected client/server net.Conn pair backed by a real
// loopback TCP socket. A TCP pair (rather than net.Pipe) is used because the
// proxies set read/write deadlines and rely on buffered, non-synchronous I/O
// semantics that net.Pipe does not provide.
func pipeConn(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	return client, r.c
}

// jsonConfig builds a datatypes.JSON target config from a string map (matching
// decodeTargetConfig's flat-map shape).
func jsonConfig(t *testing.T, m map[string]string) datatypes.JSON {
	t.Helper()
	return datatypes.JSON(mustMarshal(t, m))
}

// mustMarshal is a tiny JSON helper local to the gateway test package.
func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return b
}
