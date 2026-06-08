package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// --- unit tests -----------------------------------------------------------

func TestVNCEncryptChallengeKnownAnswer(t *testing.T) {
	// The DES result must be deterministic for a fixed challenge+password so the
	// upstream (which knows the same password) can verify it. We assert the
	// round-trip property the mock upstream relies on: encrypting the same
	// challenge with the same password yields identical 16 bytes, and a
	// different password yields different bytes.
	challenge := bytes.Repeat([]byte{0x42}, 16)
	a, err := vncEncryptChallenge(challenge, "hunter2")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	b, _ := vncEncryptChallenge(challenge, "hunter2")
	if !bytes.Equal(a, b) {
		t.Fatal("same key produced different responses")
	}
	c, _ := vncEncryptChallenge(challenge, "different")
	if bytes.Equal(a, c) {
		t.Fatal("different key produced identical response")
	}
	if len(a) != 16 {
		t.Fatalf("response len = %d", len(a))
	}
}

func TestReverseBits(t *testing.T) {
	cases := map[byte]byte{0x01: 0x80, 0x80: 0x01, 0xff: 0xff, 0x00: 0x00, 0x0f: 0xf0}
	for in, want := range cases {
		if got := reverseBits(in); got != want {
			t.Fatalf("reverseBits(0x%02x) = 0x%02x, want 0x%02x", in, got, want)
		}
	}
}

func TestReadRFBClientMessageFraming(t *testing.T) {
	// A KeyEvent (8 bytes) followed by a ClientCutText must each be read whole.
	key := []byte{rfbCMsgKeyEvent, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41}
	cut := []byte{rfbCMsgClientCutText, 0, 0, 0}
	cut = append(cut, 0, 0, 0, 5) // length 5
	cut = append(cut, []byte("hello")...)
	r := bytes.NewReader(append(append([]byte{}, key...), cut...))

	m1, t1, err := readRFBClientMessage(r)
	if err != nil || t1 != rfbCMsgKeyEvent || !bytes.Equal(m1, key) {
		t.Fatalf("key event framing: %v %d %v", err, t1, m1)
	}
	m2, t2, err := readRFBClientMessage(r)
	if err != nil || t2 != rfbCMsgClientCutText || !bytes.Equal(m2, cut) {
		t.Fatalf("cut text framing: %v %d %v", err, t2, m2)
	}
}

// --- integration test with a mock VNC upstream ----------------------------

// mockVNCUpstream is a minimal RFB server doing VNC Authentication (DES
// challenge-response) with the gateway's injected vault password, then a
// ServerInit, then it records the client messages it receives. A real VNC
// server is impractical in a unit test; this double verifies the proxy injects
// the vault credential correctly and that gated clipboard pastes never arrive.
type mockVNCUpstream struct {
	password string

	mu      sync.Mutex
	cutText [][]byte
	keys    int
}

func (m *mockVNCUpstream) counts() (keys int, cuts int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keys, len(m.cutText)
}

func (m *mockVNCUpstream) serve(t *testing.T, conn net.Conn) {
	defer conn.Close()

	if _, err := conn.Write([]byte(rfbProtocolVersion)); err != nil {
		return
	}
	var cliVer [12]byte
	if _, err := io.ReadFull(conn, cliVer[:]); err != nil {
		return
	}
	// Offer VNC Auth only.
	if _, err := conn.Write([]byte{0x01, rfbSecVNCAuth}); err != nil {
		return
	}
	var pick [1]byte
	if _, err := io.ReadFull(conn, pick[:]); err != nil || pick[0] != rfbSecVNCAuth {
		return
	}
	challenge, err := generateVNCChallenge()
	if err != nil {
		return
	}
	if _, err := conn.Write(challenge); err != nil {
		return
	}
	var resp [16]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return
	}
	want, _ := vncEncryptChallenge(challenge, m.password)
	if !bytes.Equal(resp[:], want) {
		_, _ = conn.Write([]byte{0, 0, 0, 1}) // SecurityResult failed
		return
	}
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil { // SecurityResult OK
		return
	}
	// ClientInit → ServerInit.
	var ci [1]byte
	if _, err := io.ReadFull(conn, ci[:]); err != nil {
		return
	}
	if _, err := conn.Write(buildServerInit("mock-vnc")); err != nil {
		return
	}
	// Record client messages.
	for {
		msg, mt, err := readRFBClientMessage(conn)
		if err != nil {
			return
		}
		m.mu.Lock()
		switch mt {
		case rfbCMsgKeyEvent:
			m.keys++
		case rfbCMsgClientCutText:
			m.cutText = append(m.cutText, msg)
		}
		m.mu.Unlock()
	}
}

func TestVNCProxyEndToEnd(t *testing.T) {
	env := newProxyTestEnv(t)
	env.seedDeny(t, "no-clipboard", []string{"*"}, []string{"cmd:clipboard*"})

	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer upLn.Close()
	up := &mockVNCUpstream{password: "vault-vnc-pass"}
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go up.serve(t, c)
		}
	}()

	target := env.createTarget(t, models.PAMProtocolVNC, upLn.Addr().String(), pam.Secret{Password: "vault-vnc-pass"})
	token := env.mintToken(t, target.ID, "alice")

	proxy, err := NewVNCProxy(VNCProxyConfig{Broker: env.broker, Sessions: env.sessions, Hub: env.hub, Store: env.store, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewVNCProxy: %v", err)
	}
	client, server := pipeConn(t)
	defer client.Close()
	done := make(chan struct{})
	go func() {
		proxy.Handle(context.Background(), server)
		close(done)
	}()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	vncOperatorHandshake(t, client, "alice", token)

	// Allowed KeyEvent.
	if _, err := client.Write([]byte{rfbCMsgKeyEvent, 0x01, 0, 0, 0, 0, 0, 0x41}); err != nil {
		t.Fatalf("write key: %v", err)
	}
	// Denied clipboard paste — dropped by the gateway, never reaches upstream.
	cut := append([]byte{rfbCMsgClientCutText, 0, 0, 0, 0, 0, 0, 5}, []byte("hello")...)
	if _, err := client.Write(cut); err != nil {
		t.Fatalf("write cut: %v", err)
	}
	// Second KeyEvent so we can wait for the upstream to have processed past the
	// dropped clipboard message deterministically.
	if _, err := client.Write([]byte{rfbCMsgKeyEvent, 0x01, 0, 0, 0, 0, 0, 0x42}); err != nil {
		t.Fatalf("write key2: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if k, _ := up.counts(); k >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	keys, cuts := up.counts()
	if keys != 2 {
		t.Fatalf("upstream key events = %d, want 2", keys)
	}
	if cuts != 0 {
		t.Fatalf("denied clipboard paste reached upstream (%d cut-texts)", cuts)
	}

	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not return")
	}

	rows := env.sessionRows(t)
	if len(rows) != 1 || rows[0].State != models.PAMSessionClosed {
		t.Fatalf("session not closed: %+v", rows)
	}
	cmds := env.commandRows(t, rows[0].ID)
	var sawDeny bool
	for _, c := range cmds {
		if c.Decision == models.PAMDecisionDeny && bytes.Contains([]byte(c.Command), []byte("clipboard")) {
			sawDeny = true
		}
	}
	if !sawDeny {
		t.Fatalf("expected a denied clipboard command row, got %+v", cmds)
	}

	frames := parseFrames(t, env.store.put[rows[0].ID.String()])
	var sawAnnotation bool
	for _, f := range frames {
		if f.dir == DirControl && bytes.Contains(f.payload, []byte("clipboard paste denied")) {
			sawAnnotation = true
		}
	}
	if !sawAnnotation {
		t.Fatal("recording missing clipboard deny annotation")
	}
}

// --- test helpers ---------------------------------------------------------

// vncOperatorHandshake drives the operator (client) side of the gateway's
// VeNCrypt-Plain handshake and the ClientInit/ServerInit exchange.
func vncOperatorHandshake(t *testing.T, conn net.Conn, user, token string) {
	t.Helper()
	var ver [12]byte
	if _, err := io.ReadFull(conn, ver[:]); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if _, err := conn.Write([]byte(rfbProtocolVersion)); err != nil {
		t.Fatalf("write version: %v", err)
	}
	// Security types.
	var n [1]byte
	if _, err := io.ReadFull(conn, n[:]); err != nil {
		t.Fatalf("read sec count: %v", err)
	}
	types := make([]byte, n[0])
	if _, err := io.ReadFull(conn, types); err != nil {
		t.Fatalf("read sec types: %v", err)
	}
	if !containsByte(types, rfbSecVeNCrypt) {
		t.Fatalf("gateway did not offer VeNCrypt: %v", types)
	}
	if _, err := conn.Write([]byte{rfbSecVeNCrypt}); err != nil {
		t.Fatalf("pick vencrypt: %v", err)
	}
	// VeNCrypt version.
	var sv [2]byte
	if _, err := io.ReadFull(conn, sv[:]); err != nil {
		t.Fatalf("read vencrypt ver: %v", err)
	}
	if _, err := conn.Write([]byte{0x00, 0x02}); err != nil {
		t.Fatalf("write vencrypt ver: %v", err)
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil || ack[0] != 0 {
		t.Fatalf("vencrypt version not acked: %v %d", err, ack[0])
	}
	// Sub-types.
	var sn [1]byte
	if _, err := io.ReadFull(conn, sn[:]); err != nil {
		t.Fatalf("read subtype count: %v", err)
	}
	subs := make([]byte, int(sn[0])*4)
	if _, err := io.ReadFull(conn, subs); err != nil {
		t.Fatalf("read subtypes: %v", err)
	}
	chosen := make([]byte, 4)
	binary.BigEndian.PutUint32(chosen, veNCryptPlain)
	if _, err := conn.Write(chosen); err != nil {
		t.Fatalf("write subtype: %v", err)
	}
	// Plain credentials.
	creds := make([]byte, 8)
	binary.BigEndian.PutUint32(creds[0:4], uint32(len(user)))
	binary.BigEndian.PutUint32(creds[4:8], uint32(len(token)))
	creds = append(creds, []byte(user)...)
	creds = append(creds, []byte(token)...)
	if _, err := conn.Write(creds); err != nil {
		t.Fatalf("write creds: %v", err)
	}
	// SecurityResult.
	var sr [4]byte
	if _, err := io.ReadFull(conn, sr[:]); err != nil {
		t.Fatalf("read security result: %v", err)
	}
	if binary.BigEndian.Uint32(sr[:]) != 0 {
		t.Fatalf("operator auth failed, security result = %d", binary.BigEndian.Uint32(sr[:]))
	}
	// ClientInit → ServerInit.
	if _, err := conn.Write([]byte{0x01}); err != nil {
		t.Fatalf("write ClientInit: %v", err)
	}
	if _, err := readServerInit(conn); err != nil {
		t.Fatalf("read ServerInit: %v", err)
	}
}

func buildServerInit(name string) []byte {
	b := make([]byte, 24)
	binary.BigEndian.PutUint16(b[0:2], 1024) // width
	binary.BigEndian.PutUint16(b[2:4], 768)  // height
	// 16 bytes pixel format left zero (good enough for the proxy, which does not
	// interpret it).
	binary.BigEndian.PutUint32(b[20:24], uint32(len(name)))
	return append(b, []byte(name)...)
}
