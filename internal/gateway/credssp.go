package gateway

import (
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // NTLMv2/CredSSP are defined in terms of MD5/MD4/RC4 by [MS-NLMP]/[MS-CSSP]; their use here is mandated by the wire protocol, not a security choice.
	"crypto/rand"
	"crypto/rc4" //nolint:gosec // see above: RC4 is the NTLM sealing cipher.
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/md4" //nolint:gosec,staticcheck // MD4 is the NTLM one-way function (NTOWF) per [MS-NLMP]; required by the protocol.
)

// This file implements the client side of CredSSP/NLA ([MS-CSSP]) with NTLMv2
// ([MS-NLMP]) so the RDP proxy can authenticate to upstream Windows servers that
// require Network Level Authentication (the modern default). The gateway runs
// CredSSP as the client over the already-established upstream TLS channel,
// proving possession of the JIT vault credential and delivering it to the server
// as TSCredentials — so the credential is never carried in clear text and the
// upstream never needs to be downgraded to standard RDP security.
//
// The cryptography here (MD4, MD5, HMAC-MD5, RC4) is dictated by the NTLM wire
// protocol; it is not a discretionary algorithm choice.

// NTLM negotiate flags ([MS-NLMP] 2.2.2.5).
const (
	ntlmNegotiateUnicode    uint32 = 0x00000001
	ntlmRequestTarget       uint32 = 0x00000004
	ntlmNegotiateSign       uint32 = 0x00000010
	ntlmNegotiateSeal       uint32 = 0x00000020
	ntlmNegotiateNTLM       uint32 = 0x00000200
	ntlmNegotiateAlwaysSign uint32 = 0x00008000
	ntlmNegotiateExtended   uint32 = 0x00080000 // EXTENDED_SESSIONSECURITY
	ntlmNegotiateTargetInfo uint32 = 0x00800000
	ntlmNegotiate128        uint32 = 0x20000000
	ntlmNegotiateKeyExch    uint32 = 0x40000000
)

// ntlmClientFlags is the flag set the gateway advertises: Unicode NTLMv2 with
// extended session security, signing, sealing and key exchange — the set
// required to seal the CredSSP pubKeyAuth and authInfo tokens.
const ntlmClientFlags = ntlmNegotiateUnicode | ntlmRequestTarget | ntlmNegotiateSign |
	ntlmNegotiateSeal | ntlmNegotiateNTLM | ntlmNegotiateAlwaysSign | ntlmNegotiateExtended |
	ntlmNegotiateTargetInfo | ntlmNegotiate128 | ntlmNegotiateKeyExch

var ntlmSignature = []byte("NTLMSSP\x00")

// AV_PAIR ids ([MS-NLMP] 2.2.2.1).
const (
	msvAvEOL       uint16 = 0x0000
	msvAvFlags     uint16 = 0x0006
	msvAvTimestamp uint16 = 0x0007
)

// credsspVersion is the CredSSP protocol version the gateway advertises. Version
// 6 uses the client-nonce + SHA-256 public-key binding ([MS-CSSP] 3.1.5).
const credsspVersion = 6

// CredSSP public-key binding hash magic strings ([MS-CSSP] 3.1.5). The trailing
// NUL is part of the constant.
var (
	credsspClientToServerMagic = []byte("CredSSP Client-To-Server Binding Hash\x00")
	credsspServerToClientMagic = []byte("CredSSP Server-To-Client Binding Hash\x00")
)

// --- ASN.1 structures ([MS-CSSP] 2.2) -------------------------------------

type negoData struct {
	NegoToken []byte `asn1:"explicit,tag:0"`
}

type tsRequest struct {
	Version     int        `asn1:"explicit,tag:0"`
	NegoTokens  []negoData `asn1:"explicit,optional,tag:1"`
	AuthInfo    []byte     `asn1:"explicit,optional,tag:2"`
	PubKeyAuth  []byte     `asn1:"explicit,optional,tag:3"`
	ErrorCode   int        `asn1:"explicit,optional,tag:4"`
	ClientNonce []byte     `asn1:"explicit,optional,tag:5"`
}

type tsPasswordCreds struct {
	DomainName []byte `asn1:"explicit,tag:0"`
	UserName   []byte `asn1:"explicit,tag:1"`
	Password   []byte `asn1:"explicit,tag:2"`
}

type tsCredentials struct {
	CredType    int    `asn1:"explicit,tag:0"`
	Credentials []byte `asn1:"explicit,tag:1"`
}

// --- NTLMv2 primitives ----------------------------------------------------

// ntowfv2 computes the NTLMv2 one-way function: HMAC-MD5 keyed by MD4(UTF16LE(
// password)) over UTF16LE(UPPER(user) || domain) ([MS-NLMP] 3.3.2).
func ntowfv2(user, password, domain string) []byte {
	h := md4.New() //nolint:gosec // protocol-mandated
	_, _ = h.Write(utf16LEBytes(password))
	ntlmHash := h.Sum(nil)

	mac := hmac.New(md5.New, ntlmHash)
	mac.Write(utf16LEBytes(strings.ToUpper(user)))
	mac.Write(utf16LEBytes(domain))
	return mac.Sum(nil)
}

// buildNTLMNegotiate builds the NTLM NEGOTIATE_MESSAGE (type 1). Domain and
// workstation are omitted; only the flags matter to the server.
func buildNTLMNegotiate(flags uint32) []byte {
	msg := make([]byte, 32)
	copy(msg[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], 1) // MessageType
	binary.LittleEndian.PutUint32(msg[12:16], flags)
	// DomainNameFields (16) and WorkstationFields (24) left zero (len/maxlen/off=0).
	return msg
}

// ntlmChallenge holds the fields the client needs from a CHALLENGE_MESSAGE.
type ntlmChallenge struct {
	serverChallenge [8]byte
	targetInfo      []byte
	flags           uint32
}

// parseNTLMChallenge parses a CHALLENGE_MESSAGE (type 2) ([MS-NLMP] 2.2.1.2).
func parseNTLMChallenge(b []byte) (ntlmChallenge, error) {
	var c ntlmChallenge
	if len(b) < 48 {
		return c, errors.New("ntlm challenge too short")
	}
	if !hmac.Equal(b[0:8], ntlmSignature) || binary.LittleEndian.Uint32(b[8:12]) != 2 {
		return c, errors.New("not an NTLM challenge message")
	}
	copy(c.serverChallenge[:], b[24:32])
	c.flags = binary.LittleEndian.Uint32(b[20:24])
	tiLen := int(binary.LittleEndian.Uint16(b[40:42]))
	tiOff := int(binary.LittleEndian.Uint32(b[44:48]))
	if tiLen > 0 {
		if tiOff < 0 || tiOff+tiLen > len(b) {
			return c, errors.New("ntlm challenge target info out of range")
		}
		c.targetInfo = append([]byte(nil), b[tiOff:tiOff+tiLen]...)
	}
	return c, nil
}

// avPairTimestamp returns the MsvAvTimestamp value from an AV_PAIR list, or the
// current time as a Windows FILETIME if absent.
func avPairTimestamp(targetInfo []byte) []byte {
	if ts := avPairFind(targetInfo, msvAvTimestamp); ts != nil {
		return ts
	}
	ft := uint64(time.Now().Unix())*10000000 + 116444736000000000
	out := make([]byte, 8)
	binary.LittleEndian.PutUint64(out, ft)
	return out
}

// avPairFind returns the value of the first AV_PAIR with the given id, or nil.
func avPairFind(targetInfo []byte, id uint16) []byte {
	for i := 0; i+4 <= len(targetInfo); {
		avID := binary.LittleEndian.Uint16(targetInfo[i : i+2])
		avLen := int(binary.LittleEndian.Uint16(targetInfo[i+2 : i+4]))
		i += 4
		if avID == msvAvEOL {
			return nil
		}
		if i+avLen > len(targetInfo) {
			return nil
		}
		if avID == id {
			return append([]byte(nil), targetInfo[i:i+avLen]...)
		}
		i += avLen
	}
	return nil
}

// avPairsWithMICFlag returns a copy of the AV_PAIR list with MsvAvFlags present
// and bit 0x2 (MIC provided) set, preserving all other pairs and the EOL
// terminator ([MS-NLMP] 3.1.5.1.2).
func avPairsWithMICFlag(targetInfo []byte) []byte {
	var out []byte
	sawFlags := false
	for i := 0; i+4 <= len(targetInfo); {
		avID := binary.LittleEndian.Uint16(targetInfo[i : i+2])
		avLen := int(binary.LittleEndian.Uint16(targetInfo[i+2 : i+4]))
		if avID == msvAvEOL {
			break
		}
		if i+4+avLen > len(targetInfo) {
			break
		}
		val := targetInfo[i+4 : i+4+avLen]
		if avID == msvAvFlags {
			sawFlags = true
			flags := uint32(0)
			if avLen >= 4 {
				flags = binary.LittleEndian.Uint32(val)
			}
			flags |= 0x00000002
			out = appendAVPair(out, msvAvFlags, leUint32(flags))
		} else {
			out = appendAVPair(out, avID, val)
		}
		i += 4 + avLen
	}
	if !sawFlags {
		out = appendAVPair(out, msvAvFlags, leUint32(0x00000002))
	}
	out = appendAVPair(out, msvAvEOL, nil) // EOL terminator
	return out
}

func appendAVPair(b []byte, id uint16, val []byte) []byte {
	var hdr [4]byte
	binary.LittleEndian.PutUint16(hdr[0:2], id)
	binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(val)))
	b = append(b, hdr[:]...)
	return append(b, val...)
}

func leUint32(v uint32) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, v)
	return out
}

// ntlmAuthResult bundles the AUTHENTICATE message and the keys derived from it.
type ntlmAuthResult struct {
	authenticate       []byte
	exportedSessionKey []byte
}

// buildNTLMAuthenticate computes the NTLMv2 response and assembles the
// AUTHENTICATE_MESSAGE (type 3), including the MIC over the three NTLM messages
// ([MS-NLMP] 3.1.5.1.2). negotiate and challenge are the raw type-1/type-2
// bytes already exchanged, needed for the MIC.
func buildNTLMAuthenticate(user, password, domain string, chal ntlmChallenge, negotiate, challenge []byte) (ntlmAuthResult, error) {
	ntowf := ntowfv2(user, password, domain)

	var clientChallenge [8]byte
	if _, err := rand.Read(clientChallenge[:]); err != nil {
		return ntlmAuthResult{}, err
	}
	timestamp := avPairTimestamp(chal.targetInfo)
	responseTargetInfo := avPairsWithMICFlag(chal.targetInfo)

	// temp = Resp(1) HiResp(1) Z(6) timestamp(8) clientChallenge(8) Z(4)
	//        targetInfo Z(4)
	temp := make([]byte, 0, 28+len(responseTargetInfo)+4)
	temp = append(temp, 0x01, 0x01, 0, 0, 0, 0, 0, 0)
	temp = append(temp, timestamp...)
	temp = append(temp, clientChallenge[:]...)
	temp = append(temp, 0, 0, 0, 0)
	temp = append(temp, responseTargetInfo...)
	temp = append(temp, 0, 0, 0, 0)

	mac := hmac.New(md5.New, ntowf)
	mac.Write(chal.serverChallenge[:])
	mac.Write(temp)
	ntProof := mac.Sum(nil)
	ntChallengeResponse := append(append([]byte(nil), ntProof...), temp...)

	skMac := hmac.New(md5.New, ntowf)
	skMac.Write(ntProof)
	sessionBaseKey := skMac.Sum(nil)

	// With MsvAvTimestamp present the client sends Z(24) for LmChallengeResponse.
	lmChallengeResponse := make([]byte, 24)

	exportedSessionKey := make([]byte, 16)
	if _, err := rand.Read(exportedSessionKey); err != nil {
		return ntlmAuthResult{}, err
	}
	rc4Cipher, err := rc4.NewCipher(sessionBaseKey) //nolint:gosec // protocol-mandated
	if err != nil {
		return ntlmAuthResult{}, err
	}
	encryptedRandomSessionKey := make([]byte, 16)
	rc4Cipher.XORKeyStream(encryptedRandomSessionKey, exportedSessionKey)

	auth := assembleAuthenticate(domain, user, lmChallengeResponse, ntChallengeResponse, encryptedRandomSessionKey)

	// MIC = HMAC_MD5(ExportedSessionKey, negotiate || challenge || auth-with-MIC-zeroed).
	micMac := hmac.New(md5.New, exportedSessionKey)
	micMac.Write(negotiate)
	micMac.Write(challenge)
	micMac.Write(auth)
	mic := micMac.Sum(nil)
	copy(auth[micOffset:micOffset+16], mic)

	return ntlmAuthResult{authenticate: auth, exportedSessionKey: exportedSessionKey}, nil
}

// micOffset is the byte offset of the 16-byte MIC field in the AUTHENTICATE
// message header (8 sig + 4 type + 6*8 field descriptors + 4 flags + 8 version).
const micOffset = 8 + 4 + 6*8 + 4 + 8 // 72

// assembleAuthenticate lays out an AUTHENTICATE_MESSAGE with a zeroed MIC; the
// caller fills the MIC afterwards.
func assembleAuthenticate(domain, user string, lm, nt, encSessionKey []byte) []byte {
	domainB := utf16LEBytes(domain)
	userB := utf16LEBytes(user)
	// Header is fixed at payloadStart bytes (through the MIC); variable payload
	// follows in this order: LM, NT, Domain, User, Workstation(empty), EncKey.
	const payloadStart = micOffset + 16 // 88
	hdr := make([]byte, payloadStart)
	copy(hdr[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(hdr[8:12], 3) // MessageType

	var payload []byte
	put := func(fieldOff int, data []byte) {
		off := payloadStart + len(payload)
		binary.LittleEndian.PutUint16(hdr[fieldOff:fieldOff+2], uint16(len(data)))
		binary.LittleEndian.PutUint16(hdr[fieldOff+2:fieldOff+4], uint16(len(data)))
		binary.LittleEndian.PutUint32(hdr[fieldOff+4:fieldOff+8], uint32(off))
		payload = append(payload, data...)
	}
	put(12, lm)            // LmChallengeResponseFields
	put(20, nt)            // NtChallengeResponseFields
	put(28, domainB)       // DomainNameFields
	put(36, userB)         // UserNameFields
	put(44, nil)           // WorkstationFields
	put(52, encSessionKey) // EncryptedRandomSessionKeyFields

	binary.LittleEndian.PutUint32(hdr[60:64], ntlmClientFlags)
	// Version (8 bytes at 64) left zero; MIC (16 bytes at 72) left zero.
	return append(hdr, payload...)
}

// --- NTLM message signing/sealing ([MS-NLMP] 3.4) -------------------------

// ntlmSealKeys derives the four directional signing/sealing keys from the
// exported session key.
type ntlmSealKeys struct {
	clientSigning []byte
	serverSigning []byte
	clientSeal    *rc4.Cipher
	serverSeal    *rc4.Cipher
}

func deriveNTLMKeys(exportedSessionKey []byte) (*ntlmSealKeys, error) {
	clientSign := md5sum(exportedSessionKey, []byte("session key to client-to-server signing key magic constant\x00"))
	serverSign := md5sum(exportedSessionKey, []byte("session key to server-to-client signing key magic constant\x00"))
	clientSealKey := md5sum(exportedSessionKey, []byte("session key to client-to-server sealing key magic constant\x00"))
	serverSealKey := md5sum(exportedSessionKey, []byte("session key to server-to-client sealing key magic constant\x00"))
	cs, err := rc4.NewCipher(clientSealKey) //nolint:gosec // protocol-mandated
	if err != nil {
		return nil, err
	}
	ss, err := rc4.NewCipher(serverSealKey) //nolint:gosec // protocol-mandated
	if err != nil {
		return nil, err
	}
	return &ntlmSealKeys{clientSigning: clientSign, serverSigning: serverSign, clientSeal: cs, serverSeal: ss}, nil
}

func md5sum(parts ...[]byte) []byte {
	h := md5.New() //nolint:gosec // protocol-mandated
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return h.Sum(nil)
}

// gssWrap seals message and produces the NTLM security token (signature ||
// sealed-data) used for CredSSP pubKeyAuth/authInfo ([MS-NLMP] 3.4.3/3.4.4 with
// extended session security and key exchange).
func gssWrap(seal *rc4.Cipher, signingKey []byte, seq uint32, message []byte) []byte {
	sealed := make([]byte, len(message))
	seal.XORKeyStream(sealed, message)

	var seqb [4]byte
	binary.LittleEndian.PutUint32(seqb[:], seq)
	mac := hmac.New(md5.New, signingKey)
	mac.Write(seqb[:])
	mac.Write(message)
	checksum := mac.Sum(nil)[:8]
	encChecksum := make([]byte, 8)
	seal.XORKeyStream(encChecksum, checksum)

	sig := make([]byte, 16)
	binary.LittleEndian.PutUint32(sig[0:4], 1) // version
	copy(sig[4:12], encChecksum)
	binary.LittleEndian.PutUint32(sig[12:16], seq)
	return append(sig, sealed...)
}

// gssUnwrap verifies and decrypts an NTLM security token produced by gssWrap.
func gssUnwrap(seal *rc4.Cipher, signingKey []byte, seq uint32, token []byte) ([]byte, error) {
	if len(token) < 16 {
		return nil, errors.New("ntlm token too short")
	}
	sig := token[:16]
	sealed := token[16:]
	message := make([]byte, len(sealed))
	seal.XORKeyStream(message, sealed)

	var seqb [4]byte
	binary.LittleEndian.PutUint32(seqb[:], seq)
	mac := hmac.New(md5.New, signingKey)
	mac.Write(seqb[:])
	mac.Write(message)
	checksum := mac.Sum(nil)[:8]
	encChecksum := make([]byte, 8)
	seal.XORKeyStream(encChecksum, checksum)

	if !hmac.Equal(encChecksum, sig[4:12]) {
		return nil, errors.New("ntlm signature mismatch")
	}
	if binary.LittleEndian.Uint32(sig[12:16]) != seq {
		return nil, errors.New("ntlm sequence mismatch")
	}
	return message, nil
}

// --- CredSSP client driver ------------------------------------------------

// credsspClientAuth runs the CredSSP/NLA client exchange over conn (the upstream
// TLS connection), authenticating with the vault credential and delivering it as
// TSCredentials. pubKeyInfo is the server's TLS SubjectPublicKeyInfo, bound into
// the handshake to defeat MITM ([MS-CSSP] 3.1.5).
func credsspClientAuth(conn io.ReadWriter, pubKeyInfo []byte, user, password, domain string) error {
	negotiate := buildNTLMNegotiate(ntlmClientFlags)
	if err := writeTSRequest(conn, tsRequest{Version: credsspVersion, NegoTokens: []negoData{{NegoToken: negotiate}}}); err != nil {
		return fmt.Errorf("send negotiate: %w", err)
	}

	challResp, err := readTSRequest(conn)
	if err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}
	if len(challResp.NegoTokens) == 0 {
		return errors.New("credssp challenge missing nego token")
	}
	challengeBytes := challResp.NegoTokens[0].NegoToken
	chal, err := parseNTLMChallenge(challengeBytes)
	if err != nil {
		return err
	}

	authRes, err := buildNTLMAuthenticate(user, password, domain, chal, negotiate, challengeBytes)
	if err != nil {
		return fmt.Errorf("build authenticate: %w", err)
	}
	keys, err := deriveNTLMKeys(authRes.exportedSessionKey)
	if err != nil {
		return err
	}

	clientNonce := make([]byte, 32)
	if _, err := rand.Read(clientNonce); err != nil {
		return err
	}
	pubKeyAuth := gssWrap(keys.clientSeal, keys.clientSigning, 0, credsspBindingHash(credsspClientToServerMagic, clientNonce, pubKeyInfo))

	if err := writeTSRequest(conn, tsRequest{
		Version:     credsspVersion,
		NegoTokens:  []negoData{{NegoToken: authRes.authenticate}},
		PubKeyAuth:  pubKeyAuth,
		ClientNonce: clientNonce,
	}); err != nil {
		return fmt.Errorf("send authenticate: %w", err)
	}

	pubKeyResp, err := readTSRequest(conn)
	if err != nil {
		return fmt.Errorf("read pubkey response: %w", err)
	}
	if pubKeyResp.ErrorCode != 0 {
		return fmt.Errorf("credssp server error 0x%08x", uint32(pubKeyResp.ErrorCode))
	}
	if len(pubKeyResp.PubKeyAuth) == 0 {
		return errors.New("credssp pubkey response missing pubKeyAuth")
	}
	serverHash, err := gssUnwrap(keys.serverSeal, keys.serverSigning, 0, pubKeyResp.PubKeyAuth)
	if err != nil {
		return fmt.Errorf("verify server pubkey auth: %w", err)
	}
	expected := credsspBindingHash(credsspServerToClientMagic, clientNonce, pubKeyInfo)
	if !hmac.Equal(serverHash, expected) {
		return errors.New("credssp server public-key binding mismatch (possible MITM)")
	}

	creds, err := marshalTSCredentials(domain, user, password)
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}
	authInfo := gssWrap(keys.clientSeal, keys.clientSigning, 1, creds)
	if err := writeTSRequest(conn, tsRequest{Version: credsspVersion, AuthInfo: authInfo}); err != nil {
		return fmt.Errorf("send authinfo: %w", err)
	}
	return nil
}

// credsspBindingHash computes the SHA-256 public-key binding hash for the given
// direction magic, client nonce and SubjectPublicKeyInfo ([MS-CSSP] 3.1.5).
func credsspBindingHash(magic, nonce, pubKeyInfo []byte) []byte {
	h := sha256.New()
	h.Write(magic)
	h.Write(nonce)
	h.Write(pubKeyInfo)
	return h.Sum(nil)
}

// marshalTSCredentials encodes the password credential as DER TSCredentials with
// UTF-16LE string fields ([MS-CSSP] 2.2.1.2). An ASN.1 marshalling failure is
// returned to the caller rather than swallowed, so the gateway never sends an
// empty/garbage sealed AuthInfo (which the server would reject anyway) and the
// authentication failure surfaces with a clear error.
func marshalTSCredentials(domain, user, password string) ([]byte, error) {
	pwCreds := tsPasswordCreds{
		DomainName: utf16LEBytes(domain),
		UserName:   utf16LEBytes(user),
		Password:   utf16LEBytes(password),
	}
	inner, err := asn1.Marshal(pwCreds)
	if err != nil {
		return nil, fmt.Errorf("marshal TSPasswordCreds: %w", err)
	}
	creds := tsCredentials{CredType: 1, Credentials: inner}
	out, err := asn1.Marshal(creds)
	if err != nil {
		return nil, fmt.Errorf("marshal TSCredentials: %w", err)
	}
	return out, nil
}

// parseTSPasswordCreds decodes a TSCredentials DER blob into its password
// credential. Used to validate the delivered credential (e.g. in tests).
func parseTSPasswordCreds(der []byte) (tsPasswordCreds, error) {
	var creds tsCredentials
	if _, err := asn1.Unmarshal(der, &creds); err != nil {
		return tsPasswordCreds{}, err
	}
	var pw tsPasswordCreds
	if _, err := asn1.Unmarshal(creds.Credentials, &pw); err != nil {
		return tsPasswordCreds{}, err
	}
	return pw, nil
}

// --- TSRequest wire framing -----------------------------------------------

// writeTSRequest DER-encodes and writes a TSRequest to the stream.
func writeTSRequest(w io.Writer, req tsRequest) error {
	b, err := asn1.Marshal(req)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// readTSRequest reads exactly one DER-encoded TSRequest from the stream.
func readTSRequest(r io.Reader) (tsRequest, error) {
	der, err := readDERElement(r)
	if err != nil {
		return tsRequest{}, err
	}
	var req tsRequest
	if _, err := asn1.Unmarshal(der, &req); err != nil {
		return tsRequest{}, err
	}
	return req, nil
}

// maxDERElement bounds a single CredSSP DER message to guard against a hostile
// length prefix.
const maxDERElement = 1 << 20

// readDERElement reads one complete DER TLV element (tag + definite length +
// content) from r, returning the full encoding. CredSSP TSRequests are always a
// definite-length SEQUENCE, so the indefinite form is rejected.
func readDERElement(r io.Reader) ([]byte, error) {
	var first [2]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return nil, err
	}
	tag := first[0]
	lenByte := first[1]
	out := []byte{tag, lenByte}

	var contentLen int
	if lenByte&0x80 == 0 {
		contentLen = int(lenByte)
	} else {
		n := int(lenByte & 0x7f)
		if n == 0 || n > 4 {
			return nil, fmt.Errorf("unsupported DER length form (%d bytes)", n)
		}
		lenBuf := make([]byte, n)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return nil, err
		}
		for _, b := range lenBuf {
			contentLen = contentLen<<8 | int(b)
		}
		out = append(out, lenBuf...)
	}
	if contentLen < 0 || contentLen > maxDERElement {
		return nil, fmt.Errorf("DER element too large (%d bytes)", contentLen)
	}
	content := make([]byte, contentLen)
	if _, err := io.ReadFull(r, content); err != nil {
		return nil, err
	}
	return append(out, content...), nil
}
