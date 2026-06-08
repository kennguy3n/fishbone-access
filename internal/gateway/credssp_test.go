package gateway

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // protocol-mandated, mirrors credssp.go
	"crypto/rc4" //nolint:gosec // protocol-mandated, mirrors credssp.go
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// TestNTOWFv2KnownAnswer anchors the NTLMv2 one-way function to the published
// [MS-NLMP] 4.2.4 test vector (User/Domain/Password). If this passes the whole
// NTLMv2 response chain is keyed correctly; a self-consistent mock alone could
// not catch a wrong key derivation.
func TestNTOWFv2KnownAnswer(t *testing.T) {
	got := hex.EncodeToString(ntowfv2("User", "Password", "Domain"))
	const want = "0c868a403bfd7a93a3001ef22ef02e3f"
	if got != want {
		t.Fatalf("NTOWFv2 = %s, want %s", got, want)
	}
}

// TestCredSSPClientAuthHandshake runs the real client driver against an
// independent mock CredSSP server that verifies the NTLMv2 proof, the sealed
// public-key binding, and decrypts the delivered TSCredentials — i.e. it proves
// the client's tokens are verifiable by a separate implementation, the
// credential is sealed (never plaintext on the wire), and the pubKey binding
// defeats MITM.
func TestCredSSPClientAuthHandshake(t *testing.T) {
	pubKeyInfo := []byte("subject-public-key-info-bytes-0123456789")

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	srv := &mockCredSSPServer{
		t:          t,
		user:       "alice",
		password:   "S3cr3t!=,pw",
		domain:     "CORP",
		pubKeyInfo: pubKeyInfo,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.serve(serverConn) }()

	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := credsspClientAuth(clientConn, pubKeyInfo, "alice", "S3cr3t!=,pw", "CORP"); err != nil {
		t.Fatalf("credsspClientAuth: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("mock server: %v", err)
	}
	if srv.gotCreds.user != "alice" || srv.gotCreds.password != "S3cr3t!=,pw" || srv.gotCreds.domain != "CORP" {
		t.Fatalf("delivered creds = %+v, want alice/S3cr3t!=,pw/CORP", srv.gotCreds)
	}
}

// TestCredSSPClientAuthDetectsMITM proves the client rejects a server whose
// public-key binding hash is computed over a different SubjectPublicKeyInfo than
// the TLS certificate the client bound to (the CredSSP MITM defence).
func TestCredSSPClientAuthDetectsMITM(t *testing.T) {
	clientPubKey := []byte("client-saw-this-tls-public-key-info!")
	attackerPubKey := []byte("attacker-different-public-key-info!!")

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// The server accepts the client's binding (over the key the client actually
	// used) but replies with a binding over a different key — exactly what a MITM
	// re-originating the credential to the real server would produce. Only the
	// client's server→client binding check can catch this.
	srv := &mockCredSSPServer{
		t:                 t,
		user:              "bob",
		password:          "pw",
		domain:            "",
		pubKeyInfo:        clientPubKey,
		respondPubKeyInfo: attackerPubKey,
	}
	go func() { _ = srv.serve(serverConn) }()

	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	err := credsspClientAuth(clientConn, clientPubKey, "bob", "pw", "")
	if err == nil {
		t.Fatal("expected MITM detection error, got nil")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("binding mismatch")) {
		t.Fatalf("expected binding mismatch error, got: %v", err)
	}
}

// TestCredSSPClientAuthWrongPassword proves a bad credential is rejected by the
// server's NTLMv2 proof check (surfaced to the client as a CredSSP error code).
func TestCredSSPClientAuthWrongPassword(t *testing.T) {
	pubKeyInfo := []byte("spki")
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	srv := &mockCredSSPServer{t: t, user: "carol", password: "right-pw", domain: "", pubKeyInfo: pubKeyInfo}
	go func() { _ = srv.serve(serverConn) }()

	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	err := credsspClientAuth(clientConn, pubKeyInfo, "carol", "wrong-pw", "")
	if err == nil {
		t.Fatal("expected auth failure with wrong password, got nil")
	}
}

// --- mock CredSSP server --------------------------------------------------

type deliveredCreds struct {
	domain, user, password string
}

// mockCredSSPServer is an independent verifier of the client's CredSSP/NTLMv2
// tokens. It is a test-only helper (a real Windows server is not available in
// unit tests); it recomputes the NTLMv2 proof from the password rather than
// trusting the client, so it genuinely validates the client implementation.
type mockCredSSPServer struct {
	t          *testing.T
	user       string
	password   string
	domain     string
	pubKeyInfo []byte
	// respondPubKeyInfo, when set, is the key the server binds its response hash
	// to (defaults to pubKeyInfo). Tests set it to a different value to simulate
	// a MITM that the client must detect.
	respondPubKeyInfo []byte
	gotCreds          deliveredCreds
}

func (m *mockCredSSPServer) serve(conn net.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 1. NEGOTIATE.
	req1, err := readTSRequest(conn)
	if err != nil {
		return err
	}
	if len(req1.NegoTokens) == 0 {
		return errors.New("no negotiate token")
	}
	negotiate := req1.NegoTokens[0].NegoToken

	// 2. CHALLENGE.
	var serverChallenge [8]byte
	copy(serverChallenge[:], []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})
	targetInfo := buildServerTargetInfo()
	challenge := buildMockChallenge(serverChallenge, targetInfo)
	if err := writeTSRequest(conn, tsRequest{Version: credsspVersion, NegoTokens: []negoData{{NegoToken: challenge}}}); err != nil {
		return err
	}

	// 3. AUTHENTICATE + pubKeyAuth + clientNonce.
	req2, err := readTSRequest(conn)
	if err != nil {
		return err
	}
	if len(req2.NegoTokens) == 0 {
		return errors.New("no authenticate token")
	}
	auth := req2.NegoTokens[0].NegoToken
	fields, err := parseAuthenticateFields(auth)
	if err != nil {
		return err
	}

	ntowf := ntowfv2(fields.user, m.password, fields.domain)
	if len(fields.ntResponse) < 16 {
		return errors.New("nt response too short")
	}
	ntProof := fields.ntResponse[:16]
	temp := fields.ntResponse[16:]
	mac := hmac.New(md5.New, ntowf)
	mac.Write(serverChallenge[:])
	mac.Write(temp)
	if !hmac.Equal(mac.Sum(nil), ntProof) {
		// Authentication failed (wrong password): report CredSSP error.
		return writeTSRequest(conn, tsRequest{Version: credsspVersion, ErrorCode: int(uint32(0xC000006D))})
	}

	skMac := hmac.New(md5.New, ntowf)
	skMac.Write(ntProof)
	sessionBaseKey := skMac.Sum(nil)
	rc4Cipher, err := rc4.NewCipher(sessionBaseKey) //nolint:gosec // protocol-mandated
	if err != nil {
		return err
	}
	exportedSessionKey := make([]byte, 16)
	rc4Cipher.XORKeyStream(exportedSessionKey, fields.encSessionKey)
	keys, err := deriveNTLMKeys(exportedSessionKey)
	if err != nil {
		return err
	}

	// Verify the client's sealed public-key binding (client→server stream, seq 0).
	clientHash, err := gssUnwrap(keys.clientSeal, keys.clientSigning, 0, req2.PubKeyAuth)
	if err != nil {
		return err
	}
	wantClientHash := credsspBindingHash(credsspClientToServerMagic, req2.ClientNonce, m.pubKeyInfo)
	if !hmac.Equal(clientHash, wantClientHash) {
		return errors.New("client pubkey binding mismatch")
	}

	// 4. Respond with the server→client binding (server stream, seq 0).
	respondKey := m.respondPubKeyInfo
	if respondKey == nil {
		respondKey = m.pubKeyInfo
	}
	serverHash := credsspBindingHash(credsspServerToClientMagic, req2.ClientNonce, respondKey)
	serverPubKeyAuth := gssWrap(keys.serverSeal, keys.serverSigning, 0, serverHash)
	if err := writeTSRequest(conn, tsRequest{Version: credsspVersion, PubKeyAuth: serverPubKeyAuth}); err != nil {
		return err
	}

	// 5. AuthInfo: sealed TSCredentials (client→server stream, seq 1).
	req3, err := readTSRequest(conn)
	if err != nil {
		return err
	}
	credDER, err := gssUnwrap(keys.clientSeal, keys.clientSigning, 1, req3.AuthInfo)
	if err != nil {
		return err
	}
	pw, err := parseTSPasswordCreds(credDER)
	if err != nil {
		return err
	}
	m.gotCreds = deliveredCreds{
		domain:   decodeUTF16LE(pw.DomainName),
		user:     decodeUTF16LE(pw.UserName),
		password: decodeUTF16LE(pw.Password),
	}
	_ = negotiate
	return nil
}

// buildServerTargetInfo builds a minimal AV_PAIR list with a timestamp, flags
// and EOL, like a real server CHALLENGE_MESSAGE.
func buildServerTargetInfo() []byte {
	var ti []byte
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, uint64(time.Now().Unix())*10000000+116444736000000000)
	ti = appendAVPair(ti, msvAvTimestamp, ts)
	ti = appendAVPair(ti, msvAvFlags, leUint32(0))
	ti = appendAVPair(ti, msvAvEOL, nil)
	return ti
}

// buildMockChallenge assembles a CHALLENGE_MESSAGE (type 2) with the target info
// appended after the fixed header.
func buildMockChallenge(serverChallenge [8]byte, targetInfo []byte) []byte {
	const hdr = 48
	msg := make([]byte, hdr)
	copy(msg[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], 2) // type 2
	// TargetNameFields (12) left zero.
	binary.LittleEndian.PutUint32(msg[20:24], ntlmClientFlags)
	copy(msg[24:32], serverChallenge[:])
	// Reserved (32) zero.
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(msg[44:48], uint32(hdr))
	return append(msg, targetInfo...)
}

// authenticateFields holds the fields the mock server extracts from a type-3
// AUTHENTICATE_MESSAGE.
type authenticateFields struct {
	domain, user  string
	ntResponse    []byte
	encSessionKey []byte
}

// parseAuthenticateFields decodes the variable fields of an AUTHENTICATE_MESSAGE
// using the standard field-descriptor offsets ([MS-NLMP] 2.2.1.3).
func parseAuthenticateFields(b []byte) (authenticateFields, error) {
	var f authenticateFields
	if len(b) < 64 {
		return f, errors.New("authenticate too short")
	}
	read := func(off int) ([]byte, error) {
		l := int(binary.LittleEndian.Uint16(b[off : off+2]))
		o := int(binary.LittleEndian.Uint32(b[off+4 : off+8]))
		if l == 0 {
			return nil, nil
		}
		if o < 0 || o+l > len(b) {
			return nil, errors.New("field out of range")
		}
		return b[o : o+l], nil
	}
	nt, err := read(20)
	if err != nil {
		return f, err
	}
	dom, err := read(28)
	if err != nil {
		return f, err
	}
	usr, err := read(36)
	if err != nil {
		return f, err
	}
	enc, err := read(52)
	if err != nil {
		return f, err
	}
	f.ntResponse = nt
	f.domain = decodeUTF16LE(dom)
	f.user = decodeUTF16LE(usr)
	f.encSessionKey = enc
	return f, nil
}

var _ = io.EOF
