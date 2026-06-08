package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// TDS packet types (first byte of every TDS packet header).
const (
	tdsSQLBatch  byte = 0x01
	tdsRPC       byte = 0x03
	tdsResponse  byte = 0x04
	tdsAttention byte = 0x06
	tdsLogin7    byte = 0x10
	tdsPreLogin  byte = 0x12
)

// TDS PRELOGIN ENCRYPTION option values ([MS-TDS] 2.2.6.5). The negotiated
// outcome when the gateway advertises ENCRYPT_ON is always "encrypt the whole
// session" (TLS) or "fail" — never the awkward encrypt-login-only mode that
// only arises when the client advertises ENCRYPT_OFF — so the upstream TLS path
// here either wraps the entire connection or refuses.
const (
	tdsEncryptOff    byte = 0x00 // encryption available, off
	tdsEncryptOn     byte = 0x01 // encryption available, on
	tdsEncryptNotSup byte = 0x02 // encryption not supported
	tdsEncryptReq    byte = 0x03 // encryption required
)

// preLoginEncryptionToken is the PRELOGIN option token for the ENCRYPTION field.
const preLoginEncryptionToken byte = 0x01

// tdsHeaderLen is the fixed TDS packet header size.
const tdsHeaderLen = 8

// tdsStatusEOM marks the final packet of a TDS message.
const tdsStatusEOM byte = 0x01

// tdsDefaultPacketSize is the data payload chunk size used when the proxy
// re-frames a message it parsed. 4096 is the TDS default negotiated packet
// size, so clients and servers always accept it.
const tdsDefaultPacketSize = 4096

// maxTDSMessageSize bounds a reassembled TDS message so a peer cannot force an
// unbounded allocation by never setting the EOM bit.
const maxTDSMessageSize = 32 * 1024 * 1024

// MSSQLProxy is the gateway.ConnHandler for the SQL Server listener (:1433). It
// terminates the operator's TDS connection, answers PRELOGIN advertising no
// encryption so the LOGIN7 arrives in clear text, extracts the one-shot connect
// token from the LOGIN7 password field, redeems it, then dials the upstream and
// performs its own PRELOGIN/LOGIN7 with the JIT vault credential. The upstream's
// login response is relayed to the operator, after which the proxy frame-relays
// the session: every SQL_BATCH is decoded, gated against the 1C policy engine,
// and appended to the workspace audit hash chain before reaching the upstream;
// a denied batch fails the session closed.
//
// Upstream encryption: when the target's config sets "encrypt":"true" (or
// "tls":"true"), the gateway advertises ENCRYPT_ON in its PRELOGIN to the
// upstream and, when the server agrees, performs the TLS handshake tunnelled
// inside TDS PRELOGIN packets ([MS-TDS] 2.2.6.5) before sending LOGIN7. The
// whole gateway↔upstream session — including the injected vault credential — is
// then encrypted. The operator↔gateway hop stays clear text by design so the
// gateway can read the connect token from LOGIN7; that hop is the audited trust
// boundary on the gateway's own network. A "ca_cert" PEM in the target config
// pins the upstream identity, otherwise the gateway (the trust boundary) skips
// chain verification, mirroring the k8s and web proxies.
type MSSQLProxy struct {
	broker      *pam.Broker
	sessions    *pam.SessionManager
	hub         *SessionHub
	store       ReplayStore
	dialTimeout time.Duration
	recMaxBytes int
}

// MSSQLProxyConfig configures an MSSQLProxy.
type MSSQLProxyConfig struct {
	Broker      *pam.Broker
	Sessions    *pam.SessionManager
	Hub         *SessionHub
	Store       ReplayStore
	DialTimeout time.Duration
	RecMaxBytes int
}

// NewMSSQLProxy builds an MSSQLProxy. broker and sessions are required.
func NewMSSQLProxy(cfg MSSQLProxyConfig) (*MSSQLProxy, error) {
	if cfg.Broker == nil || cfg.Sessions == nil {
		return nil, errors.New("gateway: MSSQLProxy requires broker and session manager")
	}
	dt := cfg.DialTimeout
	if dt <= 0 {
		dt = 15 * time.Second
	}
	return &MSSQLProxy{
		broker:      cfg.Broker,
		sessions:    cfg.Sessions,
		hub:         cfg.Hub,
		store:       cfg.Store,
		dialTimeout: dt,
		recMaxBytes: cfg.RecMaxBytes,
	}, nil
}

// Handle implements gateway.ConnHandler.
func (p *MSSQLProxy) Handle(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	clientAddr := conn.RemoteAddr().String()

	token, err := p.authenticateOperator(ctx, conn)
	if err != nil {
		logger.Warnf(ctx, "mssql-proxy: operator auth from %s: %v", clientAddr, err)
		return
	}

	leased, err := p.broker.RedeemConnectToken(ctx, token, clientAddr)
	if err != nil {
		logger.Warnf(ctx, "mssql-proxy: redeem from %s failed: %v", clientAddr, err)
		return
	}
	if leased.Target.Protocol != models.PAMProtocolMSSQL {
		reconcileOrphanSession(ctx, p.sessions, leased.Session, "mssql-proxy")
		return
	}
	session := leased.Session
	logger.Infof(ctx, "mssql-proxy: session %s opened for %s → %s", session.ID, session.Subject, leased.Target.Address)

	rec := NewIORecorder(session.ID.String(), p.recMaxBytes)
	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if p.hub != nil {
		defer p.hub.Register(session.ID, session.WorkspaceID, session.Subject, rec, cancel)()
	}
	defer func() {
		flushCtx, fcancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer fcancel()
		if err := rec.Flush(flushCtx, p.store); err != nil {
			logger.Warnf(ctx, "mssql-proxy: flush replay %s: %v", session.ID, err)
		}
		if err := p.sessions.CloseSession(flushCtx, session.WorkspaceID, session.ID); err != nil {
			logger.Warnf(ctx, "mssql-proxy: close session %s: %v", session.ID, err)
		}
	}()

	upstream, loginResp, err := p.dialUpstream(sessCtx, leased)
	if err != nil {
		rec.Annotate(fmt.Sprintf("[upstream connect failed: %v]", err))
		_ = writeTDSMessage(conn, tdsResponse, buildTDSError("pam-gateway: upstream connection failed"))
		logger.Warnf(ctx, "mssql-proxy: upstream %s: %v", leased.Target.Address, err)
		return
	}
	defer func() { _ = upstream.Close() }()

	// Relay the upstream's login acknowledgement to the operator as the
	// operator's own login response; the operator never authenticated upstream —
	// the gateway did with the vault credential — but a successful LOGINACK is
	// exactly what its client needs to proceed.
	if err := writeTDSMessage(conn, tdsResponse, loginResp); err != nil {
		logger.Warnf(ctx, "mssql-proxy: relay login response: %v", err)
		return
	}
	rec.Record(DirOutput, []byte("[login acknowledged]\n"))

	p.splice(sessCtx, conn, upstream, session, rec, cancel)
}

// authenticateOperator answers PRELOGIN (no encryption) and reads the LOGIN7,
// returning the connect token carried in its password field.
func (p *MSSQLProxy) authenticateOperator(ctx context.Context, conn net.Conn) (string, error) {
	_ = ctx
	_ = conn.SetReadDeadline(time.Now().Add(p.dialTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	msgType, _, err := readTDSMessage(conn)
	if err != nil {
		return "", fmt.Errorf("read prelogin: %w", err)
	}
	if msgType != tdsPreLogin {
		return "", fmt.Errorf("expected PRELOGIN, got TDS type 0x%02x", msgType)
	}
	if err := writeTDSMessage(conn, tdsResponse, buildPreLoginResponse()); err != nil {
		return "", fmt.Errorf("write prelogin response: %w", err)
	}

	loginType, loginPayload, err := readTDSMessage(conn)
	if err != nil {
		return "", fmt.Errorf("read login7: %w", err)
	}
	if loginType != tdsLogin7 {
		return "", fmt.Errorf("expected LOGIN7, got TDS type 0x%02x", loginType)
	}
	token, err := tokenFromLogin7(loginPayload)
	if err != nil {
		return "", err
	}
	return token, nil
}

// dialUpstream connects to the upstream SQL Server and authenticates with the
// vault credential via PRELOGIN + LOGIN7, returning the connection and the raw
// login-response payload to relay to the operator. When the target requests
// encryption the gateway upgrades the connection to TLS (tunnelled over TDS
// PRELOGIN packets) before LOGIN7, so the injected credential is never sent in
// clear text to the upstream.
func (p *MSSQLProxy) dialUpstream(ctx context.Context, leased *pam.LeasedSession) (net.Conn, []byte, error) {
	d := net.Dialer{Timeout: p.dialTimeout}
	raw, err := d.DialContext(ctx, "tcp", leased.Target.Address)
	if err != nil {
		return nil, nil, fmt.Errorf("dial sqlserver: %w", err)
	}
	_ = raw.SetDeadline(time.Now().Add(p.dialTimeout))

	wantTLS, tlsCfg := upstreamTLSConfig(leased)
	encByte := tdsEncryptNotSup
	if wantTLS {
		encByte = tdsEncryptOn
	}
	if err := writeTDSMessage(raw, tdsPreLogin, buildPreLogin(encByte)); err != nil {
		_ = raw.Close()
		return nil, nil, fmt.Errorf("send prelogin: %w", err)
	}
	_, preResp, err := readTDSMessage(raw)
	if err != nil {
		_ = raw.Close()
		return nil, nil, fmt.Errorf("read prelogin response: %w", err)
	}
	srvEnc := preloginEncryptionByte(preResp)

	// conn is the connection LOGIN7 and the steady-state session ride on; it is
	// the raw socket unless TLS is negotiated, in which case it is the tls.Conn.
	conn := net.Conn(raw)
	if wantTLS {
		if srvEnc == tdsEncryptNotSup {
			_ = raw.Close()
			return nil, nil, errors.New("upstream does not support encryption but target requires it")
		}
		tlsConn, terr := tlsHandshakeOverTDS(ctx, raw, tlsCfg, p.dialTimeout)
		if terr != nil {
			_ = raw.Close()
			return nil, nil, fmt.Errorf("upstream tls handshake: %w", terr)
		}
		conn = tlsConn
	} else if srvEnc == tdsEncryptReq {
		_ = raw.Close()
		return nil, nil, errors.New("upstream requires encryption; set \"encrypt\":\"true\" on the target")
	}

	// Past this point LOGIN7 and the steady-state session ride on conn, which is
	// the tls.Conn once TLS was negotiated. Close conn (not raw) on the error
	// paths so the TLS layer sends a close_notify and tears itself down cleanly;
	// when no TLS was negotiated conn is raw, so this is equivalent there.
	user := credUser(leased)
	database := decodeTargetConfig(leased.Target.Config)["database"]
	if err := writeTDSMessage(conn, tdsLogin7, buildLogin7(user, leased.Secret.Password, database)); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("send login7: %w", err)
	}
	respType, resp, err := readTDSMessage(conn)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("read login response: %w", err)
	}
	if respType != tdsResponse {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("unexpected login response type 0x%02x", respType)
	}
	if !tdsLoginSucceeded(resp) {
		_ = conn.Close()
		return nil, nil, errors.New("upstream rejected vault credential")
	}
	_ = raw.SetDeadline(time.Time{})
	return conn, resp, nil
}

// upstreamTLSConfig reports whether the target requests upstream encryption and,
// if so, the tls.Config to use. A "ca_cert" PEM pins the upstream identity;
// otherwise the gateway (the audited trust boundary to the upstream) skips chain
// verification, mirroring the k8s and web proxies.
func upstreamTLSConfig(leased *pam.LeasedSession) (bool, *tls.Config) {
	cfg := decodeTargetConfig(leased.Target.Config)
	if cfg["encrypt"] != "true" && cfg["tls"] != "true" {
		return false, nil
	}
	host := leased.Target.Address
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if ca := cfg["ca_cert"]; ca != "" {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM([]byte(ca)) {
			tlsCfg.RootCAs = pool
		}
	} else {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // no CA pinned: the gateway is the audited trust boundary to the upstream SQL Server.
	}
	return true, tlsCfg
}

// preloginEncryptionByte extracts the ENCRYPTION option value from a PRELOGIN
// response payload, walking the option table (token, 2-byte offset, 2-byte
// length) until the terminator (0xff). Offsets are relative to the start of the
// PRELOGIN payload. If the option is absent or malformed it reports NOT_SUP,
// the safe assumption that the peer cannot encrypt.
func preloginEncryptionByte(payload []byte) byte {
	for i := 0; i+1 <= len(payload); {
		tok := payload[i]
		if tok == 0xff {
			return tdsEncryptNotSup
		}
		if i+5 > len(payload) {
			return tdsEncryptNotSup
		}
		off := int(binary.BigEndian.Uint16(payload[i+1 : i+3]))
		length := int(binary.BigEndian.Uint16(payload[i+3 : i+5]))
		if tok == preLoginEncryptionToken {
			if length >= 1 && off >= 0 && off < len(payload) {
				return payload[off]
			}
			return tdsEncryptNotSup
		}
		i += 5
	}
	return tdsEncryptNotSup
}

// tlsHandshakeOverTDS performs a TLS client handshake whose handshake records
// are tunnelled inside TDS PRELOGIN packets ([MS-TDS] 2.2.6.5), then returns a
// *tls.Conn whose subsequent reads/writes ride directly on the socket (the TLS
// record layer wraps each later TDS packet). The returned conn must be used for
// all post-PRELOGIN traffic.
func tlsHandshakeOverTDS(ctx context.Context, raw net.Conn, cfg *tls.Config, timeout time.Duration) (*tls.Conn, error) {
	wrapper := &tdsPreloginConn{Conn: raw}
	tlsConn := tls.Client(wrapper, cfg)
	hsCtx, hsCancel := context.WithTimeout(ctx, timeout)
	err := tlsConn.HandshakeContext(hsCtx)
	hsCancel()
	if err != nil {
		return nil, err
	}
	// Handshake complete: stop wrapping. Application data (LOGIN7 onward) now
	// rides as ordinary TLS records straight on the socket.
	wrapper.handshakeDone = true
	return tlsConn, nil
}

// tdsPreloginConn tunnels the TLS handshake inside TDS PRELOGIN packets. While
// handshakeDone is false, each Write from crypto/tls is emitted as a PRELOGIN
// TDS message and each Read returns the payload of one inbound PRELOGIN TDS
// message; once the handshake completes the connection passes bytes straight
// through so the tls.Conn record layer rides on the raw socket.
type tdsPreloginConn struct {
	net.Conn
	handshakeDone bool
	readBuf       []byte
}

func (c *tdsPreloginConn) Write(p []byte) (int, error) {
	if c.handshakeDone {
		return c.Conn.Write(p)
	}
	if err := writeTDSMessage(c.Conn, tdsPreLogin, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *tdsPreloginConn) Read(p []byte) (int, error) {
	// Always drain decoded handshake bytes first so none are lost when the
	// handshake completes mid-message.
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	if c.handshakeDone {
		return c.Conn.Read(p)
	}
	_, payload, err := readTDSMessage(c.Conn)
	if err != nil {
		return 0, err
	}
	if len(payload) == 0 {
		return 0, nil
	}
	n := copy(p, payload)
	c.readBuf = payload[n:]
	return n, nil
}

// splice runs the steady-state TDS frame proxy. Both relay goroutines write to
// the operator socket — the command loop emits a deny error, the reply loop
// relays upstream messages — so the operator connection is funnelled through one
// lockedWriter. Because writeTDSMessage now emits each TDS message in a single
// Write, the lockedWriter guarantees a deny error can only land between two
// upstream messages, never inside one.
func (p *MSSQLProxy) splice(ctx context.Context, operator, upstream net.Conn, session *models.PAMSession, rec *IORecorder, cancel context.CancelFunc) {
	var wg sync.WaitGroup

	operatorOut := newLockedWriter(operator)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		p.forwardOperatorMessages(ctx, operator, operatorOut, upstream, session, rec)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		p.relayUpstreamMessages(operatorOut, upstream, rec)
	}()

	go func() {
		<-ctx.Done()
		_ = operator.Close()
		_ = upstream.Close()
	}()

	wg.Wait()
}

// relayUpstreamMessages reads complete TDS messages from the upstream and writes
// each (re-framed) as a single Write through the shared lockedWriter, recording
// the payload for replay. Relaying whole messages — rather than an io.Copy that
// flushes arbitrary 32KB chunks — is what lets the lockedWriter keep a deny
// error from splitting an upstream result set on the operator socket.
func (p *MSSQLProxy) relayUpstreamMessages(operator io.Writer, upstream io.Reader, rec *IORecorder) {
	for {
		msgType, payload, err := readTDSMessage(upstream)
		if err != nil {
			return
		}
		rec.Record(DirOutput, payload)
		if err := writeTDSMessage(operator, msgType, payload); err != nil {
			return
		}
	}
}

// forwardOperatorMessages reads whole operator TDS messages, gating each
// SQL_BATCH before re-framing it to the upstream. A denied batch fails the
// session closed: TDS interleaves result-set tokens across packets, so the safe
// enforcement for an in-flight stream is to sever it rather than risk a
// desynchronised protocol state (mirrors the MySQL proxy).
func (p *MSSQLProxy) forwardOperatorMessages(ctx context.Context, operatorRead io.Reader, operatorOut io.Writer, upstream net.Conn, session *models.PAMSession, rec *IORecorder) {
	for {
		msgType, payload, err := readTDSMessage(operatorRead)
		if err != nil {
			return
		}
		switch msgType {
		case tdsSQLBatch:
			sql := decodeSQLBatch(payload)
			rec.Record(DirInput, []byte(sql+"\n"))
			decision, derr := p.sessions.LogCommand(ctx, session, sql)
			if derr != nil || !decision.Allowed() {
				reason := decision.Reason
				if reason == "" {
					reason = "denied by command policy"
				}
				rec.Annotate(fmt.Sprintf("[batch denied: %s]", reason))
				_ = writeTDSMessage(operatorOut, tdsResponse, buildTDSError("pam-gateway: "+reason))
				return
			}
		case tdsRPC:
			// RPC carries parameterised calls (e.g. sp_executesql). Record the
			// raw call for audit; gating of dynamic SQL within RPC is out of scope
			// for this proxy and such calls are forwarded transparently.
			rec.Record(DirInput, []byte("[rpc call]\n"))
			_, _ = p.sessions.LogCommand(ctx, session, "rpc")
		case tdsAttention:
			// Attention (cancel) — forward so the operator can interrupt a query.
		}
		if err := writeTDSMessage(upstream, msgType, payload); err != nil {
			return
		}
	}
}

// --- TDS wire helpers -----------------------------------------------------

// readTDSMessage reassembles a full TDS message across one or more packets,
// returning the message type (from the first packet) and the concatenated
// payload. It stops when a packet with the EOM status bit is seen.
func readTDSMessage(r io.Reader) (msgType byte, payload []byte, err error) {
	var total int
	first := true
	for {
		var hdr [tdsHeaderLen]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return 0, nil, err
		}
		pktType := hdr[0]
		status := hdr[1]
		length := int(binary.BigEndian.Uint16(hdr[2:4]))
		if length < tdsHeaderLen {
			return 0, nil, fmt.Errorf("invalid TDS packet length %d", length)
		}
		dataLen := length - tdsHeaderLen
		total += dataLen
		if total > maxTDSMessageSize {
			return 0, nil, errors.New("TDS message exceeds size cap")
		}
		if dataLen > 0 {
			buf := make([]byte, dataLen)
			if _, err := io.ReadFull(r, buf); err != nil {
				return 0, nil, err
			}
			payload = append(payload, buf...)
		}
		if first {
			msgType = pktType
			first = false
		}
		if status&tdsStatusEOM != 0 {
			return msgType, payload, nil
		}
	}
}

// writeTDSMessage frames payload into TDS packets of at most
// tdsDefaultPacketSize data bytes, setting the EOM bit on the final packet. The
// whole multi-packet message is assembled into one buffer and emitted in a
// single Write so the message is atomic on the wire: when the destination is a
// lockedWriter shared by two goroutines (the operator socket), a concurrent
// write cannot be spliced between this message's packets.
func writeTDSMessage(w io.Writer, msgType byte, payload []byte) error {
	var buf []byte
	packetID := byte(1)
	for first := true; first || len(payload) > 0; first = false {
		chunk := payload
		if len(chunk) > tdsDefaultPacketSize-tdsHeaderLen {
			chunk = chunk[:tdsDefaultPacketSize-tdsHeaderLen]
		}
		payload = payload[len(chunk):]
		status := byte(0x00)
		if len(payload) == 0 {
			status = tdsStatusEOM
		}
		hdr := [tdsHeaderLen]byte{}
		hdr[0] = msgType
		hdr[1] = status
		binary.BigEndian.PutUint16(hdr[2:4], uint16(tdsHeaderLen+len(chunk)))
		hdr[4], hdr[5] = 0x00, 0x00 // SPID
		hdr[6] = packetID
		hdr[7] = 0x00 // Window
		buf = append(buf, hdr[:]...)
		buf = append(buf, chunk...)
		packetID++
	}
	if _, err := w.Write(buf); err != nil {
		return err
	}
	return nil
}

// buildPreLoginResponse builds a PRELOGIN response advertising VERSION and
// ENCRYPTION = NOT_SUP (0x02) so the operator sends LOGIN7 in clear text and the
// connect token can be read from the password field.
func buildPreLoginResponse() []byte {
	return buildPreLogin(0x02)
}

// buildPreLoginRequest builds a clear-text PRELOGIN (ENCRYPTION = NOT_SUP) as an
// operator/client would send it. The gateway's own upstream PRELOGIN is built
// directly via buildPreLogin so it can advertise ENCRYPT_ON when the target
// requests encryption.
func buildPreLoginRequest() []byte {
	return buildPreLogin(tdsEncryptNotSup)
}

// buildPreLogin assembles a PRELOGIN packet body with VERSION and ENCRYPTION
// options.
func buildPreLogin(encryption byte) []byte {
	// Two options (VERSION, ENCRYPTION) → option table is 2*5 + 1 terminator.
	const tableLen = 2*5 + 1
	version := []byte{0x10, 0x00, 0x00, 0x00, 0x00, 0x00} // 16.0.0.0
	enc := []byte{encryption}

	var b []byte
	// VERSION option (token 0x00).
	b = append(b, 0x00)
	b = appendUint16BE(b, tableLen)
	b = appendUint16BE(b, uint16(len(version)))
	// ENCRYPTION option (token 0x01).
	b = append(b, 0x01)
	b = appendUint16BE(b, tableLen+uint16(len(version)))
	b = appendUint16BE(b, uint16(len(enc)))
	// Terminator.
	b = append(b, 0xff)
	// Data.
	b = append(b, version...)
	b = append(b, enc...)
	return b
}

// tdsLoginSucceeded reports whether a login response token stream contains a
// LOGINACK (0xAD) and no ERROR (0xAA). It walks the stream token-by-token,
// skipping the USHORT-length-prefixed tokens that appear in a login response
// (ENVCHANGE 0xE3, INFO 0xAB, ERROR 0xAA, LOGINACK 0xAD) so that a 0xAA/0xAD
// byte occurring *inside* a token's payload is never mistaken for a token
// type. It stops at the terminating DONE token (0xFD/0xFE/0xFF) or at any token
// shape it does not recognise.
func tdsLoginSucceeded(payload []byte) bool {
	sawLoginAck := false
	for i := 0; i < len(payload); {
		tok := payload[i]
		i++
		switch tok {
		case 0xaa: // ERROR
			return false
		case 0xad: // LOGINACK
			sawLoginAck = true
			fallthrough
		case 0xab, 0xe3: // INFO, ENVCHANGE — all USHORT length-prefixed
			if i+2 > len(payload) {
				return sawLoginAck
			}
			l := int(binary.LittleEndian.Uint16(payload[i : i+2]))
			i += 2 + l
		case 0xfd, 0xfe, 0xff: // DONE / DONEPROC / DONEINPROC: 12-byte fixed body
			return sawLoginAck
		default:
			// Unrecognised token shape: stop rather than risk mis-skipping.
			return sawLoginAck
		}
	}
	return sawLoginAck
}

// tokenFromLogin7 extracts the connect token from the password field of a
// LOGIN7 message. The TDS password is stored UCS-2 with each byte
// nibble-swapped then XORed with 0xA5; this reverses that obfuscation and
// decodes the UTF-16LE result.
func tokenFromLogin7(payload []byte) (string, error) {
	// Fixed LOGIN7 fields occupy the first 36 bytes; the OffsetLength block
	// follows. ibPassword/cchPassword are the third pair (HostName, UserName,
	// Password) at offsets 44/46 from the start of the LOGIN7 payload.
	const ibPasswordPos = 44
	if len(payload) < ibPasswordPos+4 {
		return "", errors.New("LOGIN7 too short for password offsets")
	}
	ibPassword := binary.LittleEndian.Uint16(payload[ibPasswordPos : ibPasswordPos+2])
	cchPassword := binary.LittleEndian.Uint16(payload[ibPasswordPos+2 : ibPasswordPos+4])
	if cchPassword == 0 {
		return "", errors.New("LOGIN7 has empty password")
	}
	start := int(ibPassword)
	byteLen := int(cchPassword) * 2
	if start < 0 || start+byteLen > len(payload) {
		return "", errors.New("LOGIN7 password offset out of range")
	}
	obf := payload[start : start+byteLen]
	clear := make([]byte, len(obf))
	for i, b := range obf {
		swapped := (b >> 4) | (b << 4)
		clear[i] = swapped ^ 0xa5
	}
	return decodeUTF16LE(clear), nil
}

// decodeSQLBatch extracts the SQL text from a SQL_BATCH payload. TDS 7.2+
// prefixes the batch with an ALL_HEADERS block (a 4-byte total length followed
// by headers); when present it is skipped. The remaining bytes are the batch
// text in UTF-16LE.
func decodeSQLBatch(payload []byte) string {
	if len(payload) >= 4 {
		total := binary.LittleEndian.Uint32(payload[:4])
		// A plausible ALL_HEADERS block: total length is within the payload and
		// large enough to hold at least its own length field. Otherwise treat the
		// payload as bare UCS-2 text (older TDS versions omit ALL_HEADERS).
		if total >= 4 && int(total) <= len(payload) {
			return decodeUTF16LE(payload[total:])
		}
	}
	return decodeUTF16LE(payload)
}

// buildLogin7 assembles a LOGIN7 message authenticating as user/password
// against the optional initial database. Only the fields the upstream needs
// (HostName, UserName, Password, AppName, Database) are populated; the rest are
// zero-length.
func buildLogin7(user, password, database string) []byte {
	hostName := utf16LEBytes("shieldnet-pam")
	userName := utf16LEBytes(user)
	passwordEnc := obfuscateTDSPassword(password)
	appName := utf16LEBytes("shieldnet-pam-gateway")
	dbName := utf16LEBytes(database)

	// Fixed portion is 36 bytes, then the OffsetLength block. The variable data
	// is laid out after the OffsetLength block + the 6-byte ClientID.
	// OffsetLength block layout (each ib/cch pair is 4 bytes):
	//   HostName, UserName, Password, AppName, ServerName, Unused, CltIntName,
	//   Language, Database  (9 pairs = 36 bytes), then ClientID (6 bytes),
	//   then SSPI/AtchDBFile/ChangePassword (3 pairs = 12 bytes) + cbSSPILong(4).
	const fixedLen = 36
	const offsetBlockLen = 9*4 + 6 + 3*4 + 4 // 58
	dataStart := fixedLen + offsetBlockLen

	// Track each field's offset explicitly as it is appended to the data block.
	var data []byte
	offHost := dataStart
	data = append(data, hostName...)
	offUser := dataStart + len(data)
	data = append(data, userName...)
	offPass := dataStart + len(data)
	data = append(data, passwordEnc...)
	offApp := dataStart + len(data)
	data = append(data, appName...)
	offDB := dataStart + len(data)
	data = append(data, dbName...)

	totalLen := dataStart + len(data)

	buf := make([]byte, fixedLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(totalLen)) // Length
	// TDSVersion 7.4 (0x74000004).
	binary.LittleEndian.PutUint32(buf[4:8], 0x74000004)
	binary.LittleEndian.PutUint32(buf[8:12], tdsDefaultPacketSize) // PacketSize
	binary.LittleEndian.PutUint32(buf[12:16], 0x07000000)          // ClientProgVer
	binary.LittleEndian.PutUint32(buf[16:20], 0)                   // ClientPID
	binary.LittleEndian.PutUint32(buf[20:24], 0)                   // ConnectionID
	buf[24] = 0x00                                                 // OptionFlags1
	buf[25] = 0x00                                                 // OptionFlags2
	buf[26] = 0x00                                                 // TypeFlags
	buf[27] = 0x00                                                 // OptionFlags3
	binary.LittleEndian.PutUint32(buf[28:32], 0)                   // ClientTimeZone
	binary.LittleEndian.PutUint32(buf[32:36], 0)                   // ClientLCID

	ob := make([]byte, 0, offsetBlockLen)
	appendOL := func(off, charCount int) {
		ob = appendUint16LE(ob, uint16(off))
		ob = appendUint16LE(ob, uint16(charCount))
	}
	appendOL(offHost, len(hostName)/2)
	appendOL(offUser, len(userName)/2)
	appendOL(offPass, len(passwordEnc)/2)
	appendOL(offApp, len(appName)/2)
	appendOL(0, 0)                      // ServerName
	appendOL(0, 0)                      // Unused/Extension
	appendOL(0, 0)                      // CltIntName
	appendOL(0, 0)                      // Language
	appendOL(offDB, len(dbName)/2)      // Database
	ob = append(ob, make([]byte, 6)...) // ClientID (MAC)
	appendOL(0, 0)                      // SSPI
	appendOL(0, 0)                      // AtchDBFile
	appendOL(0, 0)                      // ChangePassword
	ob = appendUint32LE(ob, 0)          // cbSSPILong

	out := make([]byte, 0, totalLen)
	out = append(out, buf...)
	out = append(out, ob...)
	out = append(out, data...)
	return out
}

// obfuscateTDSPassword applies the TDS password obfuscation (UTF-16LE, then per
// byte: XOR 0xA5 then swap nibbles) used in the LOGIN7 password field.
func obfuscateTDSPassword(password string) []byte {
	raw := utf16LEBytes(password)
	out := make([]byte, len(raw))
	for i, b := range raw {
		x := b ^ 0xa5
		out[i] = (x << 4) | (x >> 4)
	}
	return out
}

// buildTDSError builds a TDS response payload containing an ERROR token
// followed by a DONE(error) token, used to refuse a policy-denied batch with a
// message the client surfaces to the operator.
func buildTDSError(msg string) []byte {
	text := utf16LEBytes(msg)
	server := utf16LEBytes("pam-gateway")

	var tok []byte
	// ERROR token body (everything after the 2-byte length).
	var body []byte
	body = appendUint32LE(body, 50000) // Number
	body = append(body, 0x01, 0x10)    // State, Class (>=11 ⇒ error)
	body = appendUint16LE(body, uint16(len(text)/2))
	body = append(body, text...)             // MsgText (US_VARCHAR)
	body = append(body, byte(len(server)/2)) // ServerName length (B_VARCHAR)
	body = append(body, server...)
	body = append(body, 0x00)      // ProcName length (empty)
	body = appendUint32LE(body, 1) // LineNumber

	tok = append(tok, 0xaa) // TOKEN_ERROR
	tok = appendUint16LE(tok, uint16(len(body)))
	tok = append(tok, body...)

	// DONE token: Status DONE_ERROR (0x0002), CurCmd 0, RowCount 0.
	tok = append(tok, 0xfd)
	tok = appendUint16LE(tok, 0x0002)
	tok = appendUint16LE(tok, 0x0000)
	tok = appendUint64LE(tok, 0)
	return tok
}

// --- small encoding helpers ----------------------------------------------

func utf16LEBytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(out[i*2:], r)
	}
	return out
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

func appendUint16BE(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendUint16LE(b []byte, v uint16) []byte {
	return append(b, byte(v), byte(v>>8))
}

func appendUint32LE(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func appendUint64LE(b []byte, v uint64) []byte {
	return append(b,
		byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
		byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
}

// ensure strings import is used (TrimSpace on decoded SQL elsewhere if needed).
var _ = strings.TrimSpace
