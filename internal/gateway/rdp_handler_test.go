package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// --- unit tests -----------------------------------------------------------

func TestMstshashTokenExtraction(t *testing.T) {
	cr := buildConnectionRequest("tok-abc123", rdpNegProtocolHybrid)
	pdu := append([]byte{0x03, 0x00, 0x00, 0x00}, cr...)
	binary.BigEndian.PutUint16(pdu[2:4], uint16(len(pdu)))
	got, err := mstshashToken(pdu)
	if err != nil {
		t.Fatalf("mstshashToken: %v", err)
	}
	if got != "tok-abc123" {
		t.Fatalf("token = %q", got)
	}
}

func TestSelectedProtocol(t *testing.T) {
	cc := append([]byte{0x03, 0x00, 0x00, 0x00}, buildConnectionConfirm(rdpNegProtocolSSL)...)
	binary.BigEndian.PutUint16(cc[2:4], uint16(len(cc)))
	p, err := selectedProtocol(cc)
	if err != nil {
		t.Fatalf("selectedProtocol: %v", err)
	}
	if p != rdpNegProtocolSSL {
		t.Fatalf("selected = %d", p)
	}
}

func TestParseSendDataRoundTrip(t *testing.T) {
	ud := []byte("hello-rdp-userdata")
	pdu := buildSendData(mcsSendDataRequest, 1007, ud)
	ch, got, ok := parseSendData(pdu, mcsSendDataRequest)
	if !ok {
		t.Fatal("not parsed as send data")
	}
	if ch != 1007 {
		t.Fatalf("channel = %d", ch)
	}
	if !bytes.Equal(got, ud) {
		t.Fatalf("userdata = %q", got)
	}
}

func TestInjectClientInfoCredentials(t *testing.T) {
	// Operator's Client Info PDU carries placeholder creds; injection must
	// replace them with the vault credential and keep the PDU parseable.
	info := buildClientInfoUserData("OPERATOR\\bob", "placeholder-pass", "DOMAIN")
	pdu := buildSendData(mcsSendDataRequest, 1003, info)
	// credUser prefers the target's username (matching the PG/MySQL convention),
	// so the target's "vault-admin" wins over the secret's username here.
	leased := &pam.LeasedSession{
		Target: &models.PAMTarget{Username: "vault-admin"},
		Secret: pam.Secret{Username: "ignored-secret-user", Password: "vault-secret"},
	}
	out, err := injectClientInfoCredentials(pdu, info, leased)
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	_, ud, ok := parseSendData(out, mcsSendDataRequest)
	if !ok {
		t.Fatal("rewritten PDU not parseable")
	}
	user, pass, _ := decodeClientInfoUserData(ud)
	if user != "vault-admin" || pass != "vault-secret" {
		t.Fatalf("injected creds = %q / %q", user, pass)
	}
	if int(binary.BigEndian.Uint16(out[2:4])) != len(out) {
		t.Fatalf("TPKT length not fixed: hdr=%d actual=%d", binary.BigEndian.Uint16(out[2:4]), len(out))
	}
}

func TestInjectClientInfoCredentialsTwoBytePERLength(t *testing.T) {
	// Build an operator Client Info PDU whose user-data length uses the 2-byte
	// PER form with a low byte < 0x80: 300 = 0x012C encodes to [0x81, 0x2C].
	// A heuristic that decided the determinant width by inspecting the byte just
	// before the user data would see 0x2C (high bit clear), misread it as a
	// 1-byte determinant, and splice in the stray 0x81 — corrupting the PDU.
	longPass := strings.Repeat("p", 131) // user "bob" + this pass ⇒ user-data len 300
	info := buildClientInfoUserData("bob", longPass, "")
	if len(info) < 0x80 || byte(len(info))&0x80 != 0 {
		t.Fatalf("precondition: user-data len %d is not a 2-byte PER form with low byte < 0x80", len(info))
	}
	pdu := buildSendData(mcsSendDataRequest, 1003, info)
	leased := &pam.LeasedSession{
		Target: &models.PAMTarget{Username: "vault-admin"},
		Secret: pam.Secret{Username: "ignored-secret-user", Password: "vault-secret"},
	}
	out, err := injectClientInfoCredentials(pdu, info, leased)
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	_, ud, ok := parseSendData(out, mcsSendDataRequest)
	if !ok {
		t.Fatal("rewritten 2-byte-length PDU not parseable")
	}
	user, pass, _ := decodeClientInfoUserData(ud)
	if user != "vault-admin" || pass != "vault-secret" {
		t.Fatalf("injected creds = %q / %q", user, pass)
	}
	if int(binary.BigEndian.Uint16(out[2:4])) != len(out) {
		t.Fatalf("TPKT length not fixed: hdr=%d actual=%d", binary.BigEndian.Uint16(out[2:4]), len(out))
	}
}

func TestParseClientAndServerNetworkData(t *testing.T) {
	ci := buildConnectInitial([]string{"cliprdr", "rdpdr"})
	defs, ok := parseClientNetworkData(ci)
	if !ok || len(defs) != 2 || defs[0].name != "cliprdr" || defs[1].name != "rdpdr" {
		t.Fatalf("CS_NET parse = %+v ok=%v", defs, ok)
	}
	cr := buildConnectResponse([]uint16{1004, 1005})
	ids, ok := parseServerNetworkData(cr)
	if !ok || len(ids) != 2 || ids[0] != 1004 || ids[1] != 1005 {
		t.Fatalf("SC_NET parse = %v ok=%v", ids, ok)
	}
}

// --- integration test with a mock RDP upstream ----------------------------

// mockRDPUpstream is a minimal RDP server: it confirms standard RDP security,
// exchanges the GCC channel data, then records the channel ids it receives Send
// Data on and the credential carried in the Client Info PDU. A real RDP server
// is impractical in a unit test; this double verifies the proxy forces standard
// security, injects the vault credential, and never relays gated channel PDUs.
type mockRDPUpstream struct {
	serverChannelIDs []uint16

	mu           sync.Mutex
	sendChannels []uint16
	gotUser      string
	gotPass      string
}

func (m *mockRDPUpstream) snapshot() ([]uint16, string, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]uint16(nil), m.sendChannels...), m.gotUser, m.gotPass
}

func (m *mockRDPUpstream) serve(conn net.Conn) {
	defer conn.Close()
	// Connection Request → Confirm (standard RDP security).
	if _, err := readTPKT(conn); err != nil {
		return
	}
	if err := writeTPKT(conn, buildConnectionConfirm(rdpNegProtocolRDP)); err != nil {
		return
	}
	// MCS Connect Initial → Connect Response with our channel ids.
	if _, err := readTPKT(conn); err != nil {
		return
	}
	if _, err := conn.Write(buildConnectResponse(m.serverChannelIDs)); err != nil {
		return
	}
	for {
		pdu, err := readTPKT(conn)
		if err != nil {
			return
		}
		ch, ud, ok := parseSendData(pdu, mcsSendDataRequest)
		if !ok {
			continue
		}
		m.mu.Lock()
		m.sendChannels = append(m.sendChannels, ch)
		if isClientInfoPDU(ud) {
			m.gotUser, m.gotPass, _ = decodeClientInfoUserData(ud)
		}
		m.mu.Unlock()
	}
}

func TestRDPProxyEndToEnd(t *testing.T) {
	env := newProxyTestEnv(t)
	env.seedDeny(t, "no-clipboard", []string{"*"}, []string{"cmd:clipboard*"})

	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer upLn.Close()
	up := &mockRDPUpstream{serverChannelIDs: []uint16{1004, 1005}} // cliprdr, rdpdr
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go up.serve(c)
		}
	}()

	target := env.createTarget(t, models.PAMProtocolRDP, upLn.Addr().String(),
		pam.Secret{Username: "vault-admin", Password: "vault-secret"})
	token := env.mintToken(t, target.ID, "alice")

	proxy, err := NewRDPProxy(RDPProxyConfig{Broker: env.broker, Sessions: env.sessions, Hub: env.hub, Store: env.store, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewRDPProxy: %v", err)
	}
	client, server := pipeConn(t)
	defer client.Close()
	done := make(chan struct{})
	go func() {
		proxy.Handle(context.Background(), server)
		close(done)
	}()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	// Operator Connection Request with the token in the mstshash cookie.
	if err := writeTPKT(client, buildConnectionRequest(token, rdpNegProtocolHybrid)); err != nil {
		t.Fatalf("write CR: %v", err)
	}
	// Connection Confirm (standard RDP security).
	cc, err := readTPKT(client)
	if err != nil {
		t.Fatalf("read CC: %v", err)
	}
	if p, _ := selectedProtocol(cc); p != rdpNegProtocolRDP {
		t.Fatalf("operator confirm selected protocol %d", p)
	}
	// MCS Connect Initial advertising clipboard + drive channels (buildConnectInitial
	// already returns a full TPKT frame, so write it raw).
	if _, err := client.Write(buildConnectInitial([]string{"cliprdr", "rdpdr"})); err != nil {
		t.Fatalf("write connect initial: %v", err)
	}
	// Connect Response (carries SC_NET channel ids); reading it guarantees the
	// gateway has populated its channel→id gating map before we send anything on
	// those channels.
	if _, err := readTPKT(client); err != nil {
		t.Fatalf("read connect response: %v", err)
	}
	// Clipboard Send Data (channel 1004) → must be dropped by the gateway.
	if _, err := client.Write(buildSendData(mcsSendDataRequest, 1004, []byte("clipboard-format-list"))); err != nil {
		t.Fatalf("write clipboard: %v", err)
	}
	// Client Info PDU on the I/O channel (1003) → forwarded with injected creds.
	info := buildClientInfoUserData("OPERATOR\\bob", "placeholder", "")
	if _, err := client.Write(buildSendData(mcsSendDataRequest, 1003, info)); err != nil {
		t.Fatalf("write client info: %v", err)
	}

	// Wait until the upstream has received the Client Info PDU.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, u, _ := up.snapshot(); u != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	channels, gotUser, gotPass := up.snapshot()
	for _, ch := range channels {
		if ch == 1004 || ch == 1005 {
			t.Fatalf("gated channel %d reached upstream", ch)
		}
	}
	if gotUser != "vault-admin" || gotPass != "vault-secret" {
		t.Fatalf("upstream saw creds %q / %q, want vault-admin / vault-secret", gotUser, gotPass)
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
	var sawClipDeny bool
	for _, c := range env.commandRows(t, rows[0].ID) {
		if c.Command == "clipboard:redirect" && c.Decision == models.PAMDecisionDeny {
			sawClipDeny = true
		}
	}
	if !sawClipDeny {
		t.Fatal("expected denied clipboard:redirect command row")
	}
}

// --- test helpers ---------------------------------------------------------

// buildSendData frames an MCS Send Data PDU (request or indication) on a
// channel inside a TPKT/X.224-data envelope.
func buildSendData(choice uint8, channelID uint16, userData []byte) []byte {
	x224 := []byte{0x02, x224TPDUData, 0x80}
	mcs := []byte{choice << 2}
	mcs = append(mcs, 0x00, 0x07) // initiator (arbitrary)
	chb := make([]byte, 2)
	binary.BigEndian.PutUint16(chb, channelID)
	mcs = append(mcs, chb...)
	mcs = append(mcs, 0x70) // dataPriority/segmentation
	mcs = append(mcs, perWriteLength(len(userData))...)
	mcs = append(mcs, userData...)
	out := append([]byte{0x03, 0x00, 0x00, 0x00}, x224...)
	out = append(out, mcs...)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	return out
}

// buildClientInfoUserData builds a Send Data user-data payload: a 4-byte
// security header with SEC_INFO_PKT plus a UNICODE TS_INFO_PACKET.
func buildClientInfoUserData(user, pass, domain string) []byte {
	sec := make([]byte, 4)
	binary.LittleEndian.PutUint16(sec[0:2], secInfoPkt)

	dom := utf16z(domain)
	usr := utf16z(user)
	pwd := utf16z(pass)
	shell := utf16z("")
	workdir := utf16z("")

	info := make([]byte, 18)
	binary.LittleEndian.PutUint32(info[0:4], 0)           // CodePage
	binary.LittleEndian.PutUint32(info[4:8], infoUnicode) // flags
	binary.LittleEndian.PutUint16(info[8:10], uint16(len(dom)-2))
	binary.LittleEndian.PutUint16(info[10:12], uint16(len(usr)-2))
	binary.LittleEndian.PutUint16(info[12:14], uint16(len(pwd)-2))
	binary.LittleEndian.PutUint16(info[14:16], uint16(len(shell)-2))
	binary.LittleEndian.PutUint16(info[16:18], uint16(len(workdir)-2))
	info = append(info, dom...)
	info = append(info, usr...)
	info = append(info, pwd...)
	info = append(info, shell...)
	info = append(info, workdir...)
	return append(sec, info...)
}

// decodeClientInfoUserData extracts the domain-less username and password from
// a Client Info user-data payload built by buildClientInfoUserData / rewritten
// by the proxy.
func decodeClientInfoUserData(ud []byte) (user, pass string, ok bool) {
	if !isClientInfoPDU(ud) || len(ud) < 4+18 {
		return "", "", false
	}
	info := ud[4:]
	cbDomain := int(binary.LittleEndian.Uint16(info[8:10]))
	cbUser := int(binary.LittleEndian.Uint16(info[10:12]))
	cbPass := int(binary.LittleEndian.Uint16(info[12:14]))
	p := 18
	p += cbDomain + 2
	if p+cbUser+2 > len(info) {
		return "", "", false
	}
	user = decodeUTF16LE(info[p : p+cbUser])
	p += cbUser + 2
	if p+cbPass > len(info) {
		return "", "", false
	}
	pass = decodeUTF16LE(info[p : p+cbPass])
	return user, pass, true
}

// buildConnectInitial builds a minimal PDU containing a CS_NET (0xC003) block
// with the given channel names, inside a TPKT/X.224-data envelope whose MCS
// choice byte is not a Send Data choice.
func buildConnectInitial(names []string) []byte {
	var net []byte
	net = append(net, 0x03, 0xC0) // CS_NET type (little-endian 0xC003)
	blockLen := 8 + len(names)*12
	lb := make([]byte, 2)
	binary.LittleEndian.PutUint16(lb, uint16(blockLen))
	net = append(net, lb...)
	cnt := make([]byte, 4)
	binary.LittleEndian.PutUint32(cnt, uint32(len(names)))
	net = append(net, cnt...)
	for _, n := range names {
		name := make([]byte, 8)
		copy(name, n)
		net = append(net, name...)
		net = append(net, 0, 0, 0, 0) // options
	}
	// X.224 data header + a BER-ish prefix (0x7f 0x65) so parseSendData rejects it.
	body := append([]byte{0x02, x224TPDUData, 0x80, 0x7f, 0x65}, net...)
	out := append([]byte{0x03, 0x00, 0x00, 0x00}, body...)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	return out
}

// buildConnectResponse builds a minimal PDU containing an SC_NET (0x0C03) block
// with the given server channel ids.
func buildConnectResponse(ids []uint16) []byte {
	var net []byte
	net = append(net, 0x03, 0x0C) // SC_NET type (little-endian 0x0C03)
	blockLen := 8 + len(ids)*2
	lb := make([]byte, 2)
	binary.LittleEndian.PutUint16(lb, uint16(blockLen))
	net = append(net, lb...)
	net = append(net, 0xEB, 0x03) // MCSChannelId (I/O channel 1003)
	cc := make([]byte, 2)
	binary.LittleEndian.PutUint16(cc, uint16(len(ids)))
	net = append(net, cc...)
	for _, id := range ids {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, id)
		net = append(net, b...)
	}
	body := append([]byte{0x02, x224TPDUData, 0x80, 0x7f, 0x66}, net...)
	out := append([]byte{0x03, 0x00, 0x00, 0x00}, body...)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	return out
}

func utf16z(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, len(u)*2+2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(out[i*2:], r)
	}
	return out
}
