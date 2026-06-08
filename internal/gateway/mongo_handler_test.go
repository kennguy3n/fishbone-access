package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
	"golang.org/x/crypto/pbkdf2"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// --- wire-helper unit tests -----------------------------------------------

func TestMongoParseCommandOpMsg(t *testing.T) {
	var doc []byte
	idx, doc := bsoncore.AppendDocumentStart(doc)
	doc = bsoncore.AppendStringElement(doc, "drop", "victims")
	doc = bsoncore.AppendStringElement(doc, "$db", "app")
	doc, _ = bsoncore.AppendDocumentEnd(doc, idx)
	msg := buildMsgRequest(doc)

	name, _, ns, _, _, ok := parseCommand(msg)
	if !ok {
		t.Fatal("parseCommand failed on OP_MSG")
	}
	if name != "drop" {
		t.Fatalf("name = %q, want drop", name)
	}
	if ns != "app.victims" {
		t.Fatalf("ns = %q, want app.victims", ns)
	}
}

func TestMongoCommandString(t *testing.T) {
	if got := mongoCommandString("Drop", "app.coll"); got != "drop app.coll" {
		t.Fatalf("got %q", got)
	}
	if got := mongoCommandString("ping", ""); got != "ping" {
		t.Fatalf("got %q", got)
	}
}

func TestTokenFromSaslStartPLAIN(t *testing.T) {
	var doc []byte
	idx, doc := bsoncore.AppendDocumentStart(doc)
	doc = bsoncore.AppendInt32Element(doc, "saslStart", 1)
	doc = bsoncore.AppendStringElement(doc, "mechanism", "PLAIN")
	doc = bsoncore.AppendBinaryElement(doc, "payload", 0x00, []byte("\x00alice\x00tok-123"))
	doc, _ = bsoncore.AppendDocumentEnd(doc, idx)

	tok, err := tokenFromSaslStart(bsoncore.Document(doc))
	if err != nil {
		t.Fatalf("tokenFromSaslStart: %v", err)
	}
	if tok != "tok-123" {
		t.Fatalf("token = %q", tok)
	}
}

func TestTokenFromSaslStartRejectsNonPlain(t *testing.T) {
	var doc []byte
	idx, doc := bsoncore.AppendDocumentStart(doc)
	doc = bsoncore.AppendInt32Element(doc, "saslStart", 1)
	doc = bsoncore.AppendStringElement(doc, "mechanism", "SCRAM-SHA-256")
	doc = bsoncore.AppendBinaryElement(doc, "payload", 0x00, []byte("n,,n=u,r=x"))
	doc, _ = bsoncore.AppendDocumentEnd(doc, idx)
	if _, err := tokenFromSaslStart(bsoncore.Document(doc)); err == nil {
		t.Fatal("expected rejection of non-PLAIN mechanism")
	}
}

func TestParseScramServerFirst(t *testing.T) {
	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	sf, err := parseScramServerFirst("r=clientnonceServer,s=" + salt + ",i=4096")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sf.nonce != "clientnonceServer" || sf.iterations != 4096 || string(sf.salt) != "0123456789abcdef" {
		t.Fatalf("server-first parsed wrong: %+v", sf)
	}
}

func TestScramServerSignature(t *testing.T) {
	sig := []byte("0123456789abcdef0123456789abcdef")
	enc := base64.StdEncoding.EncodeToString(sig)
	// Exact v= attribute, possibly alongside extension attributes.
	got, err := scramServerSignature("v=" + enc)
	if err != nil {
		t.Fatalf("parse v=: %v", err)
	}
	if !bytes.Equal(got, sig) {
		t.Fatalf("signature mismatch")
	}
	if _, err := scramServerSignature("v=" + enc + ",extra=1"); err != nil {
		t.Fatalf("parse with extension attr: %v", err)
	}
	// A server-final error carries e=, no verifier: must fail closed.
	if _, err := scramServerSignature("e=other-error"); err == nil {
		t.Fatal("expected error for missing verifier")
	}
}

// --- integration test with a mock SCRAM-SHA-256 mongod --------------------

// mockMongoUpstream is a minimal mongod: it performs the server side of a
// SCRAM-SHA-256 conversation (RFC 7677) with the gateway, then replies {ok:1}
// to every relayed command, recording the command verbs it saw. A real mongod
// is impractical in a unit test; this double exercises the proxy's two
// contracts — inject the vault credential via SCRAM, then relay framed
// commands — against an independent SCRAM implementation.
type mockMongoUpstream struct {
	user string
	pass string

	mu   sync.Mutex
	seen []string
}

func (m *mockMongoUpstream) commands() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.seen...)
}

func (m *mockMongoUpstream) serve(conn net.Conn) {
	defer conn.Close()

	// --- SCRAM-SHA-256 server side ---
	startMsg, err := readWireMessage(conn)
	if err != nil {
		return
	}
	_, startBody, _, _, _, ok := parseCommand(startMsg)
	if !ok {
		return
	}
	_, clientFirstRaw, _ := startBody.Lookup("payload").BinaryOK()
	clientFirst := string(clientFirstRaw)
	clientFirstBare := strings.TrimPrefix(clientFirst, "n,,")
	clientNonce := scramField(clientFirstBare, "r=")

	serverNonce := clientNonce + "serverpart"
	salt := []byte("fixedsalt16bytes")
	const iters = 4096
	serverFirst := fmt.Sprintf("r=%s,s=%s,i=%d", serverNonce, base64.StdEncoding.EncodeToString(salt), iters)
	if err := m.writeScramReply(conn, 1, false, serverFirst); err != nil {
		return
	}

	contMsg, err := readWireMessage(conn)
	if err != nil {
		return
	}
	_, contBody, _, _, _, ok := parseCommand(contMsg)
	if !ok {
		return
	}
	_, clientFinalRaw, _ := contBody.Lookup("payload").BinaryOK()
	clientFinal := string(clientFinalRaw)

	saltedPassword := pbkdf2.Key([]byte(m.pass), salt, iters, sha256.Size, sha256.New)
	clientKey := scramHMAC(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	clientFinalNoProof := "c=" + scramField(clientFinal, "c=") + ",r=" + scramField(clientFinal, "r=")
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalNoProof
	clientSig := scramHMAC(storedKey[:], []byte(authMessage))
	wantProof := base64.StdEncoding.EncodeToString(xorBytes(clientKey, clientSig))
	if scramField(clientFinal, "p=") != wantProof {
		_ = m.writeError(conn, "SCRAM proof mismatch")
		return
	}
	serverKey := scramHMAC(saltedPassword, []byte("Server Key"))
	serverSig := scramHMAC(serverKey, []byte(authMessage))
	if err := m.writeScramReply(conn, 1, true, "v="+base64.StdEncoding.EncodeToString(serverSig)); err != nil {
		return
	}

	// --- relay loop ---
	for {
		msg, err := readWireMessage(conn)
		if err != nil {
			return
		}
		name, _, _, reqID, _, ok := parseCommand(msg)
		if ok {
			m.mu.Lock()
			m.seen = append(m.seen, strings.ToLower(name))
			m.mu.Unlock()
		}
		_, _ = conn.Write(buildOKReply(reqID))
	}
}

func (m *mockMongoUpstream) writeScramReply(conn net.Conn, convID int32, done bool, payload string) error {
	var doc []byte
	idx, doc := bsoncore.AppendDocumentStart(doc)
	doc = bsoncore.AppendInt32Element(doc, "conversationId", convID)
	doc = bsoncore.AppendBooleanElement(doc, "done", done)
	doc = bsoncore.AppendBinaryElement(doc, "payload", 0x00, []byte(payload))
	doc = bsoncore.AppendDoubleElement(doc, "ok", 1)
	doc, _ = bsoncore.AppendDocumentEnd(doc, idx)
	_, err := conn.Write(buildMsgReply(0, doc))
	return err
}

func (m *mockMongoUpstream) writeError(conn net.Conn, msg string) error {
	_, err := conn.Write(buildErrorReply(0, 18, "AuthenticationFailed", msg))
	return err
}

func buildOKReply(responseTo int32) []byte {
	var doc []byte
	idx, doc := bsoncore.AppendDocumentStart(doc)
	doc = bsoncore.AppendDoubleElement(doc, "ok", 1)
	doc, _ = bsoncore.AppendDocumentEnd(doc, idx)
	return buildMsgReply(responseTo, doc)
}

func scramField(s, prefix string) string {
	for _, f := range strings.Split(s, ",") {
		if strings.HasPrefix(f, prefix) {
			return f[len(prefix):]
		}
	}
	return ""
}

func TestMongoProxyEndToEnd(t *testing.T) {
	env := newProxyTestEnv(t)
	env.seedDeny(t, "no-drop", []string{"*"}, []string{"cmd:drop *"})

	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer upLn.Close()
	// Password deliberately contains '=' and ',' — RFC 5802 escapes only the
	// username, never the password fed to PBKDF2. A regression that escapes the
	// password would derive the wrong salted key and fail the SCRAM proof here.
	up := &mockMongoUpstream{user: "svc", pass: "v=ault,pa55"}
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go up.serve(c)
		}
	}()

	target := env.createTarget(t, models.PAMProtocolMongoDB, upLn.Addr().String(), pam.Secret{Username: "svc", Password: "v=ault,pa55"})
	token := env.mintToken(t, target.ID, "alice")

	proxy, err := NewMongoProxy(MongoProxyConfig{Broker: env.broker, Sessions: env.sessions, Hub: env.hub, Store: env.store, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewMongoProxy: %v", err)
	}
	client, server := pipeConn(t)
	defer client.Close()
	done := make(chan struct{})
	go func() {
		proxy.Handle(context.Background(), server)
		close(done)
	}()

	// Operator handshake: hello, then saslStart PLAIN with the connect token.
	if _, err := client.Write(buildHelloRequest()); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	helloReply := mustReadCommandDoc(t, client)
	if mechs, ok := helloReply.Lookup("saslSupportedMechs").ArrayOK(); !ok || !strings.Contains(string(mechs), "PLAIN") {
		t.Fatalf("hello did not advertise PLAIN: %v", helloReply)
	}

	if _, err := client.Write(buildPlainSaslStart("alice", token)); err != nil {
		t.Fatalf("write saslStart: %v", err)
	}
	authReply := mustReadCommandDoc(t, client)
	if okv, _ := authReply.Lookup("ok").AsFloat64OK(); okv != 1 {
		t.Fatalf("auth reply not ok: %v", authReply)
	}

	// Allowed command relays to the upstream and returns ok:1.
	if _, err := client.Write(buildFindCommand("app", "coll")); err != nil {
		t.Fatalf("write find: %v", err)
	}
	findReply := mustReadCommandDoc(t, client)
	if okv, _ := findReply.Lookup("ok").AsFloat64OK(); okv != 1 {
		t.Fatalf("find reply not ok: %v", findReply)
	}

	// Denied drop is rejected by the gateway with an Unauthorized error.
	if _, err := client.Write(buildDropCommand("app", "coll")); err != nil {
		t.Fatalf("write drop: %v", err)
	}
	dropReply := mustReadCommandDoc(t, client)
	if okv, _ := dropReply.Lookup("ok").AsFloat64OK(); okv != 0 {
		t.Fatalf("drop should be denied (ok:0), got: %v", dropReply)
	}
	if code, _ := dropReply.Lookup("code").AsInt32OK(); code != 13 {
		t.Fatalf("drop deny code = %d, want 13", code)
	}

	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not return")
	}

	// Upstream saw find but never the denied drop.
	for _, c := range up.commands() {
		if c == "drop" {
			t.Fatal("denied drop reached upstream")
		}
	}
	if seen := up.commands(); len(seen) == 0 || seen[0] != "find" {
		t.Fatalf("upstream did not receive find: %v", seen)
	}

	// Session closed and recording flushed with the deny annotation.
	rows := env.sessionRows(t)
	if len(rows) != 1 || rows[0].State != models.PAMSessionClosed {
		t.Fatalf("session not closed: %+v", rows)
	}
	frames := parseFrames(t, env.store.put[rows[0].ID.String()])
	var sawDeny bool
	for _, f := range frames {
		if f.dir == DirControl && strings.Contains(string(f.payload), "command denied") {
			sawDeny = true
		}
	}
	if !sawDeny {
		t.Fatal("recording missing drop deny annotation")
	}

	cmds := env.commandRows(t, rows[0].ID)
	var sawAllow, sawDenyCmd bool
	for _, c := range cmds {
		if c.Command == "find app.coll" && c.Decision == models.PAMDecisionAllow {
			sawAllow = true
		}
		if c.Command == "drop app.coll" && c.Decision == models.PAMDecisionDeny {
			sawDenyCmd = true
		}
	}
	if !sawAllow || !sawDenyCmd {
		t.Fatalf("command rows missing expected decisions: %+v", cmds)
	}
}

// TestMongoSCRAMRejectsBadPassword proves the client aborts when the upstream
// cannot verify the proof (wrong vault password), surfacing an auth error
// rather than silently proceeding.
func TestMongoSCRAMRejectsBadPassword(t *testing.T) {
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer upLn.Close()
	up := &mockMongoUpstream{user: "svc", pass: "correct-pass"}
	go func() {
		c, err := upLn.Accept()
		if err != nil {
			return
		}
		up.serve(c)
	}()

	conn, err := net.Dial("tcp", upLn.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	err = scramSHA256Auth(conn, 5*time.Second, "admin", "svc", "wrong-pass")
	if err == nil {
		t.Fatal("expected SCRAM auth to fail with wrong password")
	}
	if !strings.Contains(err.Error(), "SCRAM") && !errors.Is(err, errors.Unwrap(err)) {
		// Accept any non-nil error; the message should reference the upstream
		// rejection or signature failure.
		t.Logf("scram error: %v", err)
	}
}

// --- operator-side request builders (test helpers) ------------------------

func buildHelloRequest() []byte {
	var doc []byte
	idx, doc := bsoncore.AppendDocumentStart(doc)
	doc = bsoncore.AppendInt32Element(doc, "hello", 1)
	doc = bsoncore.AppendStringElement(doc, "$db", "admin")
	doc, _ = bsoncore.AppendDocumentEnd(doc, idx)
	return buildMsgRequest(doc)
}

func buildPlainSaslStart(user, token string) []byte {
	var doc []byte
	idx, doc := bsoncore.AppendDocumentStart(doc)
	doc = bsoncore.AppendInt32Element(doc, "saslStart", 1)
	doc = bsoncore.AppendStringElement(doc, "mechanism", "PLAIN")
	doc = bsoncore.AppendBinaryElement(doc, "payload", 0x00, []byte("\x00"+user+"\x00"+token))
	doc = bsoncore.AppendStringElement(doc, "$db", "admin")
	doc, _ = bsoncore.AppendDocumentEnd(doc, idx)
	return buildMsgRequest(doc)
}

func buildFindCommand(db, coll string) []byte {
	var doc []byte
	idx, doc := bsoncore.AppendDocumentStart(doc)
	doc = bsoncore.AppendStringElement(doc, "find", coll)
	doc = bsoncore.AppendStringElement(doc, "$db", db)
	doc, _ = bsoncore.AppendDocumentEnd(doc, idx)
	return buildMsgRequest(doc)
}

func buildDropCommand(db, coll string) []byte {
	var doc []byte
	idx, doc := bsoncore.AppendDocumentStart(doc)
	doc = bsoncore.AppendStringElement(doc, "drop", coll)
	doc = bsoncore.AppendStringElement(doc, "$db", db)
	doc, _ = bsoncore.AppendDocumentEnd(doc, idx)
	return buildMsgRequest(doc)
}

func mustReadCommandDoc(t *testing.T, conn net.Conn) bsoncore.Document {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	msg, err := readWireMessage(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	_, body, _, _, _, ok := parseCommand(msg)
	if !ok {
		t.Fatalf("malformed reply message")
	}
	return body
}

// silence unused import strconv if no other use arises.
var _ = strconv.Itoa
