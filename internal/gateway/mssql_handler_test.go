package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/datatypes"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// --- wire-helper unit tests -----------------------------------------------

func TestTDSMessageRoundTripMultiPacket(t *testing.T) {
	// A payload larger than one packet must reassemble byte-for-byte.
	payload := make([]byte, tdsDefaultPacketSize*2+123)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() { _ = writeTDSMessage(c1, tdsSQLBatch, payload) }()

	typ, got, err := readTDSMessage(c2)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if typ != tdsSQLBatch {
		t.Fatalf("type = 0x%02x", typ)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes want %d", len(got), len(payload))
	}
}

// TestWriteTDSMessageAtomic proves writeTDSMessage emits an entire multi-packet
// message in a single Write. That atomicity is what lets the operator socket be
// shared (via a lockedWriter) by the upstream-relay goroutine and the deny-error
// path without a deny frame ever being spliced between an upstream message's
// packets.
func TestWriteTDSMessageAtomic(t *testing.T) {
	payload := make([]byte, tdsDefaultPacketSize*3+7) // spans 4 packets
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	w := &chunkRecordingWriter{}
	if err := writeTDSMessage(w, tdsResponse, payload); err != nil {
		t.Fatalf("writeTDSMessage: %v", err)
	}
	if len(w.sizes) != 1 {
		t.Fatalf("expected 1 atomic Write for the whole message, got %d: %v", len(w.sizes), w.sizes)
	}
	// The single Write must reassemble back to the original payload.
	typ, got, err := readTDSMessage(bytes.NewReader(w.buf.Bytes()))
	if err != nil {
		t.Fatalf("readTDSMessage: %v", err)
	}
	if typ != tdsResponse || !bytes.Equal(got, payload) {
		t.Fatalf("round-trip mismatch: type=0x%02x len=%d", typ, len(got))
	}
}

// TestMSSQLRelayUpstreamMessagesFramed proves the upstream→operator relay writes
// each complete TDS message as a single atomic Write, even one spanning several
// TDS packets. Combined with the shared lockedWriter, this guarantees a deny
// error cannot split an upstream result set on the operator socket — the hazard
// the previous raw io.Copy relay left open.
func TestMSSQLRelayUpstreamMessagesFramed(t *testing.T) {
	// Two upstream messages: a small one, then one spanning multiple packets.
	small := []byte("OK")
	big := make([]byte, tdsDefaultPacketSize*2+99)
	for i := range big {
		big[i] = byte(i % 251)
	}
	var upstream bytes.Buffer
	if err := writeTDSMessage(&upstream, tdsResponse, small); err != nil {
		t.Fatalf("frame small: %v", err)
	}
	if err := writeTDSMessage(&upstream, tdsResponse, big); err != nil {
		t.Fatalf("frame big: %v", err)
	}

	w := &chunkRecordingWriter{}
	rec := NewIORecorder(context.Background(), "test-mssql-relay", 0)
	p := &MSSQLProxy{}
	p.relayUpstreamMessages(w, bytes.NewReader(upstream.Bytes()), rec)

	if len(w.sizes) != 2 {
		t.Fatalf("expected 2 atomic Writes (one per message), got %d: %v", len(w.sizes), w.sizes)
	}
	// Each relayed message must independently reassemble to its source payload.
	r := bytes.NewReader(w.buf.Bytes())
	if _, got, err := readTDSMessage(r); err != nil || !bytes.Equal(got, small) {
		t.Fatalf("first message mismatch: err=%v", err)
	}
	if _, got, err := readTDSMessage(r); err != nil || !bytes.Equal(got, big) {
		t.Fatalf("second message mismatch: err=%v", err)
	}
}

func TestLogin7PasswordRoundTrip(t *testing.T) {
	login := buildLogin7("sa", "S3cr3t-Token!", "appdb")
	tok, err := tokenFromLogin7(login)
	if err != nil {
		t.Fatalf("tokenFromLogin7: %v", err)
	}
	if tok != "S3cr3t-Token!" {
		t.Fatalf("token = %q", tok)
	}
	if got := login7Username(login); got != "sa" {
		t.Fatalf("username = %q", got)
	}
}

func TestDecodeSQLBatchWithAllHeaders(t *testing.T) {
	sql := "SELECT name FROM sys.tables"
	batch := buildSQLBatch(sql)
	if got := decodeSQLBatch(batch); got != sql {
		t.Fatalf("decoded %q, want %q", got, sql)
	}
}

func TestTDSLoginSucceeded(t *testing.T) {
	if !tdsLoginSucceeded(buildLoginAck()) {
		t.Fatal("expected LOGINACK stream to be a success")
	}
	// ERROR token stream must read as failure even though it contains a 0xAD
	// byte inside the (length-prefixed) message text.
	errStream := buildTDSError("login failed \u00ad")
	if tdsLoginSucceeded(errStream) {
		t.Fatal("expected ERROR stream to be a failure")
	}
}

func TestPreloginEncryptionByte(t *testing.T) {
	// A well-formed PRELOGIN advertising each value round-trips.
	for _, want := range []byte{tdsEncryptOff, tdsEncryptOn, tdsEncryptReq, tdsEncryptNotSup} {
		if got := preloginEncryptionByte(buildPreLogin(want)); got != want {
			t.Fatalf("preloginEncryptionByte = 0x%02x, want 0x%02x", got, want)
		}
	}
	// Malformed / truncated payloads must fail safe to NOT_SUP rather than read
	// out of range or misreport that the peer can encrypt.
	for name, payload := range map[string][]byte{
		"empty":               {},
		"truncated-option":    {preLoginEncryptionToken, 0x00},
		"offset-out-of-range": {preLoginEncryptionToken, 0x00, 0x7f, 0x00, 0x01, 0xff},
		"no-encryption-token": {0x00, 0x00, 0x06, 0x00, 0x01, 0xff, 0x10},
	} {
		if got := preloginEncryptionByte(payload); got != tdsEncryptNotSup {
			t.Fatalf("%s: preloginEncryptionByte = 0x%02x, want NOT_SUP", name, got)
		}
	}
}

// --- integration test with a mock TDS upstream ----------------------------

// mockMSSQLUpstream is a minimal SQL Server: it answers PRELOGIN, validates the
// LOGIN7 credential (the injected vault user/password), acknowledges the login,
// then replies DONE to each SQL batch while recording the batch text. A real
// SQL Server is impractical in a unit test; this double exercises the proxy's
// contract — read the operator token, inject the vault credential into its own
// LOGIN7, gate batches — against an independent TDS implementation.
type mockMSSQLUpstream struct {
	wantUser string
	wantPass string
	// tlsCfg, when set, makes the mock advertise ENCRYPT_ON in its PRELOGIN
	// response and perform the TLS server handshake (tunnelled over TDS PRELOGIN
	// packets) before reading LOGIN7, exercising the proxy's upstream-TLS path.
	tlsCfg *tls.Config

	mu     sync.Mutex
	seen   []string
	authOK bool
}

func (m *mockMSSQLUpstream) batches() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.seen...)
}

func (m *mockMSSQLUpstream) serve(rawConn net.Conn) {
	defer rawConn.Close()

	// PRELOGIN.
	if typ, _, err := readTDSMessage(rawConn); err != nil || typ != tdsPreLogin {
		return
	}
	// conn is the connection LOGIN7 and batches ride on: the raw socket, or a
	// tls.Conn after the handshake when encryption is negotiated.
	conn := rawConn
	if m.tlsCfg != nil {
		if err := writeTDSMessage(rawConn, tdsResponse, buildPreLogin(tdsEncryptOn)); err != nil {
			return
		}
		wrapper := &tdsPreloginConn{Conn: rawConn}
		tlsConn := tls.Server(wrapper, m.tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		wrapper.handshakeDone = true
		conn = tlsConn
	} else if err := writeTDSMessage(rawConn, tdsResponse, buildPreLoginResponse()); err != nil {
		return
	}
	// LOGIN7 — validate injected credential.
	typ, payload, err := readTDSMessage(conn)
	if err != nil || typ != tdsLogin7 {
		return
	}
	pass, _ := tokenFromLogin7(payload)
	user := login7Username(payload)
	if user != m.wantUser || pass != m.wantPass {
		_ = writeTDSMessage(conn, tdsResponse, buildTDSError("bad credential"))
		return
	}
	m.mu.Lock()
	m.authOK = true
	m.mu.Unlock()
	if err := writeTDSMessage(conn, tdsResponse, buildLoginAck()); err != nil {
		return
	}
	// Relay loop.
	for {
		mt, pl, err := readTDSMessage(conn)
		if err != nil {
			return
		}
		if mt == tdsSQLBatch {
			m.mu.Lock()
			m.seen = append(m.seen, decodeSQLBatch(pl))
			m.mu.Unlock()
		}
		_ = writeTDSMessage(conn, tdsResponse, buildDoneFinal())
	}
}

func TestMSSQLProxyEndToEnd(t *testing.T) {
	env := newProxyTestEnv(t)
	env.seedDeny(t, "no-drop", []string{"*"}, []string{"cmd:*drop table*"})

	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer upLn.Close()
	up := &mockMSSQLUpstream{wantUser: "sa", wantPass: "vault-pass"}
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go up.serve(c)
		}
	}()

	target := env.createTarget(t, models.PAMProtocolMSSQL, upLn.Addr().String(), pam.Secret{Username: "sa", Password: "vault-pass"})
	token := env.mintToken(t, target.ID, "alice")

	proxy, err := NewMSSQLProxy(MSSQLProxyConfig{Broker: env.broker, Sessions: env.sessions, Hub: env.hub, Store: env.store, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewMSSQLProxy: %v", err)
	}
	client, server := pipeConn(t)
	defer client.Close()
	done := make(chan struct{})
	go func() {
		proxy.Handle(context.Background(), server)
		close(done)
	}()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	// PRELOGIN handshake.
	if err := writeTDSMessage(client, tdsPreLogin, buildPreLoginRequest()); err != nil {
		t.Fatalf("write prelogin: %v", err)
	}
	if typ, _, err := readTDSMessage(client); err != nil || typ != tdsResponse {
		t.Fatalf("prelogin response: typ=0x%02x err=%v", typ, err)
	}
	// LOGIN7 carrying the connect token as the password.
	if err := writeTDSMessage(client, tdsLogin7, buildLogin7("alice", token, "appdb")); err != nil {
		t.Fatalf("write login7: %v", err)
	}
	typ, loginResp, err := readTDSMessage(client)
	if err != nil || typ != tdsResponse {
		t.Fatalf("login response: typ=0x%02x err=%v", typ, err)
	}
	if !tdsLoginSucceeded(loginResp) {
		t.Fatal("operator did not receive a successful LOGINACK")
	}

	// Allowed batch.
	if err := writeTDSMessage(client, tdsSQLBatch, buildSQLBatch("SELECT 1")); err != nil {
		t.Fatalf("write batch: %v", err)
	}
	if typ, _, err := readTDSMessage(client); err != nil || typ != tdsResponse {
		t.Fatalf("batch response: typ=0x%02x err=%v", typ, err)
	}

	// Denied batch (DROP TABLE) → gateway returns a TDS error and severs.
	if err := writeTDSMessage(client, tdsSQLBatch, buildSQLBatch("DROP TABLE secrets")); err != nil {
		t.Fatalf("write drop batch: %v", err)
	}
	_, denyResp, err := readTDSMessage(client)
	if err != nil {
		t.Fatalf("read deny response: %v", err)
	}
	if tdsLoginSucceeded(denyResp) {
		t.Fatal("denied batch should not yield a success token")
	}
	if !strings.Contains(decodeTDSErrorText(denyResp), "pam-gateway") {
		t.Fatalf("deny response missing gateway error: %q", decodeTDSErrorText(denyResp))
	}

	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not return")
	}

	for _, b := range up.batches() {
		if strings.Contains(strings.ToLower(b), "drop table") {
			t.Fatal("denied DROP TABLE reached upstream")
		}
	}
	if bs := up.batches(); len(bs) != 1 || bs[0] != "SELECT 1" {
		t.Fatalf("upstream batches = %v, want [SELECT 1]", bs)
	}

	rows := env.sessionRows(t)
	if len(rows) != 1 || rows[0].State != models.PAMSessionClosed {
		t.Fatalf("session not closed: %+v", rows)
	}
	cmds := env.commandRows(t, rows[0].ID)
	var sawAllow, sawDeny bool
	for _, c := range cmds {
		if c.Command == "SELECT 1" && c.Decision == models.PAMDecisionAllow {
			sawAllow = true
		}
		if c.Command == "DROP TABLE secrets" && c.Decision == models.PAMDecisionDeny {
			sawDeny = true
		}
	}
	if !sawAllow || !sawDeny {
		t.Fatalf("command rows missing expected decisions: %+v", cmds)
	}
}

// TestMSSQLProxyUpstreamTLS verifies that when the target requests encryption
// the proxy negotiates ENCRYPT_ON, completes the TLS handshake tunnelled over
// TDS PRELOGIN packets, and then injects the vault credential and relays a SQL
// batch entirely over the encrypted upstream connection.
func TestMSSQLProxyUpstreamTLS(t *testing.T) {
	env := newProxyTestEnv(t)

	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer upLn.Close()
	up := &mockMSSQLUpstream{wantUser: "sa", wantPass: "vault-pass", tlsCfg: testTLSConfig(t)}
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go up.serve(c)
		}
	}()

	target, err := env.vault.CreateTarget(context.Background(), pam.CreateTargetInput{
		WorkspaceID: env.workspaceID,
		Name:        "mssql-tls",
		Protocol:    models.PAMProtocolMSSQL,
		Address:     upLn.Addr().String(),
		Username:    "sa",
		Secret:      pam.Secret{Username: "sa", Password: "vault-pass"},
		Config:      datatypes.JSON(`{"encrypt":"true"}`),
		Actor:       "admin",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	token := env.mintToken(t, target.ID, "alice")

	proxy, err := NewMSSQLProxy(MSSQLProxyConfig{Broker: env.broker, Sessions: env.sessions, Hub: env.hub, Store: env.store, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewMSSQLProxy: %v", err)
	}
	client, server := pipeConn(t)
	defer client.Close()
	done := make(chan struct{})
	go func() {
		proxy.Handle(context.Background(), server)
		close(done)
	}()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	// Operator↔gateway PRELOGIN (clear text by design so the token is readable).
	if err := writeTDSMessage(client, tdsPreLogin, buildPreLoginRequest()); err != nil {
		t.Fatalf("write prelogin: %v", err)
	}
	if typ, _, err := readTDSMessage(client); err != nil || typ != tdsResponse {
		t.Fatalf("prelogin response: typ=0x%02x err=%v", typ, err)
	}
	// LOGIN7 carrying the connect token as the password.
	if err := writeTDSMessage(client, tdsLogin7, buildLogin7("alice", token, "appdb")); err != nil {
		t.Fatalf("write login7: %v", err)
	}
	typ, loginResp, err := readTDSMessage(client)
	if err != nil || typ != tdsResponse {
		t.Fatalf("login response: typ=0x%02x err=%v", typ, err)
	}
	if !tdsLoginSucceeded(loginResp) {
		t.Fatal("operator did not receive a successful LOGINACK over the TLS-backed upstream")
	}

	// A batch must relay through the encrypted upstream and be recorded.
	if err := writeTDSMessage(client, tdsSQLBatch, buildSQLBatch("SELECT 42")); err != nil {
		t.Fatalf("write batch: %v", err)
	}
	if typ, _, err := readTDSMessage(client); err != nil || typ != tdsResponse {
		t.Fatalf("batch response: typ=0x%02x err=%v", typ, err)
	}

	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not return")
	}

	if !up.authOK {
		t.Fatal("upstream never authenticated over TLS")
	}
	if bs := up.batches(); len(bs) != 1 || bs[0] != "SELECT 42" {
		t.Fatalf("upstream batches = %v, want [SELECT 42]", bs)
	}
}

// --- test helpers ---------------------------------------------------------

// login7Username decodes the UserName field of a LOGIN7 (the second
// OffsetLength pair, at offset 40). Username is not obfuscated.
func login7Username(payload []byte) string {
	const ibUserPos = 40
	if len(payload) < ibUserPos+4 {
		return ""
	}
	ib := binary.LittleEndian.Uint16(payload[ibUserPos : ibUserPos+2])
	cch := binary.LittleEndian.Uint16(payload[ibUserPos+2 : ibUserPos+4])
	start, n := int(ib), int(cch)*2
	if start+n > len(payload) {
		return ""
	}
	return decodeUTF16LE(payload[start : start+n])
}

// buildSQLBatch frames an ALL_HEADERS + UTF-16LE batch payload (the operator's
// SQL_BATCH body).
func buildSQLBatch(sql string) []byte {
	// ALL_HEADERS: a single 18-byte transaction-descriptor header is typical;
	// the exact header content is irrelevant to the proxy, only the total length
	// prefix matters for skipping.
	header := make([]byte, 22)
	binary.LittleEndian.PutUint32(header[0:4], uint32(len(header))) // total length incl. itself
	binary.LittleEndian.PutUint32(header[4:8], 18)                  // header length
	binary.LittleEndian.PutUint16(header[8:10], 0x0002)             // type: transaction descriptor
	body := append([]byte{}, header...)
	body = append(body, utf16LEBytes(sql)...)
	return body
}

// buildLoginAck builds a minimal successful login token stream: ENVCHANGE +
// LOGINACK + DONE(final).
func buildLoginAck() []byte {
	var b []byte
	// ENVCHANGE (0xE3) with a small length-prefixed body.
	b = append(b, 0xe3)
	env := []byte{0x01, 0x04, 0x61, 0x70, 0x70, 0x64} // arbitrary body
	b = appendUint16LE(b, uint16(len(env)))
	b = append(b, env...)
	// LOGINACK (0xAD).
	prog := utf16LEBytes("Microsoft SQL Server")
	var ack []byte
	ack = append(ack, 0x01)                   // Interface
	ack = appendUint32LE(ack, 0x74000004)     // TDSVersion
	ack = append(ack, byte(len(prog)/2))      // ProgName B_VARCHAR len
	ack = append(ack, prog...)                // ProgName
	ack = append(ack, 0x10, 0x00, 0x00, 0x00) // ProgVersion
	b = append(b, 0xad)
	b = appendUint16LE(b, uint16(len(ack)))
	b = append(b, ack...)
	// DONE final.
	b = append(b, buildDoneFinal()...)
	return b
}

// buildDoneFinal builds a DONE token with DONE_FINAL status.
func buildDoneFinal() []byte {
	var b []byte
	b = append(b, 0xfd)
	b = appendUint16LE(b, 0x0000) // status DONE_FINAL
	b = appendUint16LE(b, 0x0000) // curcmd
	b = appendUint64LE(b, 0)      // rowcount
	return b
}

// decodeTDSErrorText pulls the message text out of an ERROR (0xAA) token for
// assertions.
func decodeTDSErrorText(payload []byte) string {
	for i := 0; i < len(payload); {
		if payload[i] != 0xaa {
			i++
			continue
		}
		if i+2 > len(payload) {
			return ""
		}
		// Skip token type + length, Number(4) + State(1) + Class(1).
		p := i + 1 + 2 + 4 + 1 + 1
		if p+2 > len(payload) {
			return ""
		}
		cch := int(binary.LittleEndian.Uint16(payload[p : p+2]))
		p += 2
		if p+cch*2 > len(payload) {
			return ""
		}
		return decodeUTF16LE(payload[p : p+cch*2])
	}
	return ""
}
