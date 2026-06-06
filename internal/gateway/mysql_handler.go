package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // mysql_native_password mandates SHA-1; this is wire-protocol interop, not a security primitive choice.
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// MySQL capability flags (subset the proxy negotiates).
const (
	mysqlClientLongPassword     uint32 = 0x00000001
	mysqlClientConnectWithDB    uint32 = 0x00000008
	mysqlClientProtocol41       uint32 = 0x00000200
	mysqlClientTransactions     uint32 = 0x00002000
	mysqlClientSecureConnection uint32 = 0x00008000
	mysqlClientPluginAuth       uint32 = 0x00080000
)

// MySQL command bytes (first byte of a steady-state operator packet).
const (
	mysqlComQuit  = 0x01
	mysqlComQuery = 0x03
)

// These are MySQL auth-plugin *names* from the wire protocol, not credentials.
const mysqlNativePassword = "mysql_native_password" //nolint:gosec // G101: auth plugin name, not a credential
const mysqlClearPassword = "mysql_clear_password"   //nolint:gosec // G101: auth plugin name, not a credential

// MySQLProxy is the gateway.ConnHandler for the MySQL listener (:3306). It
// presents a protocol-10 handshake to the operator, forces an auth switch to
// mysql_clear_password so the one-shot connect token arrives in clear text,
// redeems it, then dials the upstream server and authenticates with the
// JIT-injected vault credential via mysql_native_password. In steady state it
// frame-proxies the connection: every COM_QUERY is gated against the 1C policy
// engine and appended to the workspace audit hash chain before it reaches the
// upstream, and a denied statement fails the session closed.
type MySQLProxy struct {
	broker      *pam.Broker
	sessions    *pam.SessionManager
	hub         *SessionHub
	store       ReplayStore
	dialTimeout time.Duration
	recMaxBytes int
}

// MySQLProxyConfig configures a MySQLProxy.
type MySQLProxyConfig struct {
	Broker      *pam.Broker
	Sessions    *pam.SessionManager
	Hub         *SessionHub
	Store       ReplayStore
	DialTimeout time.Duration
	RecMaxBytes int
}

// NewMySQLProxy builds a MySQLProxy.
func NewMySQLProxy(cfg MySQLProxyConfig) (*MySQLProxy, error) {
	if cfg.Broker == nil || cfg.Sessions == nil {
		return nil, errors.New("gateway: MySQLProxy requires broker and session manager")
	}
	dt := cfg.DialTimeout
	if dt <= 0 {
		dt = 15 * time.Second
	}
	return &MySQLProxy{
		broker:      cfg.Broker,
		sessions:    cfg.Sessions,
		hub:         cfg.Hub,
		store:       cfg.Store,
		dialTimeout: dt,
		recMaxBytes: cfg.RecMaxBytes,
	}, nil
}

// Handle implements gateway.ConnHandler.
func (p *MySQLProxy) Handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().String()

	token, opSeq, err := p.authenticateOperator(conn)
	if err != nil {
		logger.Warnf(ctx, "mysql-proxy: operator auth from %s failed: %v", clientAddr, err)
		return
	}
	leased, err := p.broker.RedeemConnectToken(ctx, token, clientAddr)
	if err != nil {
		writeMySQLError(conn, opSeq, 1045, "28000", "connect token rejected")
		logger.Warnf(ctx, "mysql-proxy: redeem from %s failed: %v", clientAddr, err)
		return
	}
	if leased.Target.Protocol != models.PAMProtocolMySQL {
		writeMySQLError(conn, opSeq, 1045, "28000", "token is not for a mysql target")
		return
	}
	session := leased.Session
	logger.Infof(ctx, "mysql-proxy: session %s opened for %s → %s", session.ID, session.Subject, leased.Target.Address)

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
			logger.Warnf(ctx, "mysql-proxy: flush replay %s: %v", session.ID, err)
		}
		if err := p.sessions.CloseSession(flushCtx, session.WorkspaceID, session.ID); err != nil {
			logger.Warnf(ctx, "mysql-proxy: close session %s: %v", session.ID, err)
		}
	}()

	upstream, err := p.dialUpstream(sessCtx, leased)
	if err != nil {
		writeMySQLError(conn, opSeq, 2003, "HY000", "upstream connection failed")
		rec.Annotate(fmt.Sprintf("[upstream connect failed: %v]", err))
		logger.Warnf(ctx, "mysql-proxy: upstream %s: %v", leased.Target.Address, err)
		return
	}
	defer upstream.Close()

	// Tell the operator authentication succeeded.
	if err := writeMySQLOK(conn, opSeq); err != nil {
		logger.Warnf(ctx, "mysql-proxy: send operator OK: %v", err)
		return
	}

	p.splice(sessCtx, conn, upstream, session, rec, cancel)
}

// authenticateOperator runs the operator-facing handshake: greeting →
// HandshakeResponse41 → AuthSwitchRequest(mysql_clear_password) → clear token.
// It returns the token and the next sequence id the OK/ERR reply must use.
func (p *MySQLProxy) authenticateOperator(conn net.Conn) (token string, nextSeq byte, err error) {
	salt := make([]byte, 20)
	if _, err := rand.Read(salt); err != nil {
		return "", 0, fmt.Errorf("generate salt: %w", err)
	}
	if err := writePacket(conn, 0, buildHandshakeV10(salt)); err != nil {
		return "", 0, fmt.Errorf("send greeting: %w", err)
	}
	// HandshakeResponse41 (normally seq 1). The operator's native-password
	// response is discarded because we switch to cleartext, but we track the
	// sequence the client actually used and derive ours from it rather than
	// hardcoding, so the AuthSwitchRequest always carries seq = clientSeq+1 even
	// for a client that numbered its response differently.
	_, hsSeq, err := readPacket(conn)
	if err != nil {
		return "", 0, fmt.Errorf("read handshake response: %w", err)
	}
	// AuthSwitchRequest → mysql_clear_password (seq = handshake response + 1).
	switchPkt := append([]byte{0xfe}, []byte(mysqlClearPassword)...)
	switchPkt = append(switchPkt, 0x00)
	if err := writePacket(conn, hsSeq+1, switchPkt); err != nil {
		return "", 0, fmt.Errorf("send auth switch: %w", err)
	}
	// Operator replies with the cleartext token (seq 3).
	pkt, seq, err := readPacket(conn)
	if err != nil {
		return "", 0, fmt.Errorf("read cleartext token: %w", err)
	}
	// The cleartext plugin sends the password null-terminated.
	token = string(trimTrailingNUL(pkt))
	return token, seq + 1, nil
}

// dialUpstream opens a TCP connection to the target and authenticates with
// mysql_native_password using the injected credential.
func (p *MySQLProxy) dialUpstream(ctx context.Context, leased *pam.LeasedSession) (net.Conn, error) {
	d := net.Dialer{Timeout: p.dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", leased.Target.Address)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", leased.Target.Address, err)
	}
	user := leased.Target.Username
	if user == "" {
		user = leased.Secret.Username
	}
	database := decodeTargetConfig(leased.Target.Config)["database"]
	if err := mysqlUpstreamAuth(conn, user, leased.Secret.Password, database); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// splice runs the steady-state frame proxy.
func (p *MySQLProxy) splice(ctx context.Context, operator, upstream net.Conn, session *models.PAMSession, rec *IORecorder, cancel context.CancelFunc) {
	var wg sync.WaitGroup

	// operator → upstream: packet-framed so COM_QUERY can be gated.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		p.forwardOperatorPackets(ctx, operator, upstream, session, rec)
	}()

	// upstream → operator: raw byte copy, recorded as output.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		_, _ = io.Copy(operator, rec.TeeReader(DirOutput, upstream))
	}()

	go func() {
		<-ctx.Done()
		_ = operator.Close()
		_ = upstream.Close()
	}()

	wg.Wait()
}

// forwardOperatorPackets reads operator packets one at a time, gating each
// COM_QUERY before forwarding. A denied query terminates the session
// (fail-closed): MySQL's half-duplex result framing means the safe enforcement
// for an in-flight stream is to sever it rather than risk a desynchronised
// protocol state.
func (p *MySQLProxy) forwardOperatorPackets(ctx context.Context, operator, upstream net.Conn, session *models.PAMSession, rec *IORecorder) {
	for {
		payload, seq, err := readPacket(operator)
		if err != nil {
			return
		}
		if len(payload) > 0 && payload[0] == mysqlComQuery {
			query := string(payload[1:])
			rec.Record(DirInput, []byte(query+"\n"))
			decision, derr := p.sessions.LogCommand(ctx, session, query)
			if derr != nil || !decision.Allowed() {
				reason := decision.Reason
				if reason == "" {
					reason = "denied by command policy"
				}
				rec.Annotate(fmt.Sprintf("[query denied: %s]", reason))
				writeMySQLError(operator, seq+1, 1142, "42000", "pam-gateway: "+reason)
				return
			}
		}
		if len(payload) > 0 && payload[0] == mysqlComQuit {
			_ = writePacket(upstream, seq, payload)
			return
		}
		if err := writePacket(upstream, seq, payload); err != nil {
			return
		}
	}
}

// --- MySQL wire helpers ---

// readPacket reads one MySQL packet, returning its payload and sequence id.
func readPacket(r io.Reader) (payload []byte, seq byte, err error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, 0, err
	}
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	seq = hdr[3]
	payload = make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, 0, err
	}
	return payload, seq, nil
}

// writePacket writes one MySQL packet with the given sequence id. Payloads at
// or over 16 MiB would require split packets, which the proxy's control-path
// messages never approach; bulk data flows through the raw upstream→operator
// copy, not this helper.
func writePacket(w io.Writer, seq byte, payload []byte) error {
	if len(payload) >= 1<<24 {
		return fmt.Errorf("gateway: mysql packet too large (%d bytes)", len(payload))
	}
	// Assemble header+payload into one buffer and emit it with a single Write
	// so the 4-byte header can never be split from its payload on the wire (a
	// future concurrent writer to the same conn would otherwise interleave bytes
	// and corrupt the MySQL framing).
	frame := make([]byte, 4+len(payload))
	frame[0] = byte(len(payload))
	frame[1] = byte(len(payload) >> 8)
	frame[2] = byte(len(payload) >> 16)
	frame[3] = seq
	copy(frame[4:], payload)
	_, err := w.Write(frame)
	return err
}

// buildHandshakeV10 builds the server greeting advertising
// mysql_native_password. salt must be 20 bytes.
func buildHandshakeV10(salt []byte) []byte {
	caps := mysqlClientLongPassword | mysqlClientConnectWithDB | mysqlClientProtocol41 |
		mysqlClientTransactions | mysqlClientSecureConnection | mysqlClientPluginAuth

	var b []byte
	b = append(b, 0x0a) // protocol version 10
	b = append(b, []byte("8.0.0-shieldnet-pam")...)
	b = append(b, 0x00)                           //nolint:gocritic // wire fields kept one-per-line: server version NUL
	b = append(b, 0x01, 0x00, 0x00, 0x00)         // connection id
	b = append(b, salt[:8]...)                    // auth-plugin-data-part-1
	b = append(b, 0x00)                           //nolint:gocritic // wire fields kept one-per-line: filler
	b = append(b, byte(caps), byte(caps>>8))      // capability flags lower
	b = append(b, 0x21)                           // charset utf8_general_ci
	b = append(b, 0x02, 0x00)                     // status flags
	b = append(b, byte(caps>>16), byte(caps>>24)) // capability flags upper
	b = append(b, 21)                             // auth-plugin-data length
	b = append(b, make([]byte, 10)...)            // reserved
	b = append(b, salt[8:20]...)                  // auth-plugin-data-part-2 (12)
	b = append(b, 0x00)                           // part-2 NUL terminator
	b = append(b, []byte(mysqlNativePassword)...) // auth plugin name
	b = append(b, 0x00)
	return b
}

// mysqlUpstreamAuth performs the client side of a mysql_native_password
// handshake against an upstream server. caching_sha2_password (MySQL 8.0
// default) and an RSA full-auth fallback are intentionally out of scope; an
// upstream that demands them returns a clear error so the operator knows to
// grant the gateway account mysql_native_password.
func mysqlUpstreamAuth(conn net.Conn, user, password, database string) error {
	greeting, _, err := readPacket(conn)
	if err != nil {
		return fmt.Errorf("read upstream greeting: %w", err)
	}
	salt, plugin, err := parseHandshakeV10(greeting)
	if err != nil {
		return err
	}
	if plugin != "" && plugin != mysqlNativePassword {
		return fmt.Errorf("gateway: upstream requires unsupported auth plugin %q (only %s is supported)", plugin, mysqlNativePassword)
	}

	scramble := scrambleNativePassword([]byte(password), salt)
	resp := buildHandshakeResponse41(user, database, scramble)
	if err := writePacket(conn, 1, resp); err != nil {
		return fmt.Errorf("send upstream handshake response: %w", err)
	}

	pkt, seq, err := readPacket(conn)
	if err != nil {
		return fmt.Errorf("read upstream auth result: %w", err)
	}
	switch {
	case len(pkt) > 0 && pkt[0] == 0x00:
		return nil // OK
	case len(pkt) > 0 && pkt[0] == 0xff:
		return fmt.Errorf("gateway: upstream rejected auth: %s", mysqlErrText(pkt))
	case len(pkt) > 0 && pkt[0] == 0xfe:
		// AuthSwitchRequest: honour a switch back to native_password with a new
		// salt; anything else is unsupported.
		newPlugin, newSalt := parseAuthSwitch(pkt)
		if newPlugin != mysqlNativePassword {
			return fmt.Errorf("gateway: upstream auth switch to unsupported plugin %q", newPlugin)
		}
		resp := scrambleNativePassword([]byte(password), newSalt)
		if err := writePacket(conn, seq+1, resp); err != nil {
			return fmt.Errorf("send upstream auth switch response: %w", err)
		}
		final, _, err := readPacket(conn)
		if err != nil {
			return fmt.Errorf("read upstream auth switch result: %w", err)
		}
		if len(final) > 0 && final[0] == 0x00 {
			return nil
		}
		return fmt.Errorf("gateway: upstream rejected auth after switch: %s", mysqlErrText(final))
	default:
		return fmt.Errorf("gateway: unexpected upstream auth response 0x%02x", firstByte(pkt))
	}
}

// parseHandshakeV10 extracts the 20-byte auth salt and plugin name from a
// server greeting.
func parseHandshakeV10(b []byte) (salt []byte, plugin string, err error) {
	if len(b) < 1 || b[0] != 0x0a {
		return nil, "", errors.New("gateway: unsupported upstream protocol version")
	}
	pos := 1
	// server version (NUL-terminated)
	end := indexByte(b[pos:], 0x00)
	if end < 0 {
		return nil, "", errors.New("gateway: malformed greeting (version)")
	}
	pos += end + 1
	if pos+4+8+1+2+1+2+2+1 > len(b) {
		return nil, "", errors.New("gateway: malformed greeting (truncated)")
	}
	pos += 4 // connection id
	salt = append(salt, b[pos:pos+8]...)
	pos += 8
	pos++    // filler
	pos += 2 // cap lower
	pos++    // charset
	pos += 2 // status
	pos += 2 // cap upper
	authLen := int(b[pos])
	pos++
	pos += 10 // reserved
	// auth-plugin-data-part-2: at least 13 bytes; total salt is authLen-1.
	part2 := authLen - 8
	if part2 < 13 {
		part2 = 13
	}
	if pos+part2 > len(b) {
		return nil, "", errors.New("gateway: malformed greeting (salt part 2)")
	}
	salt = append(salt, b[pos:pos+part2-1]...) // drop trailing NUL
	pos += part2
	if pos < len(b) {
		plugin = string(trimTrailingNUL(b[pos:]))
	}
	if len(salt) > 20 {
		salt = salt[:20]
	}
	return salt, plugin, nil
}

// buildHandshakeResponse41 builds the client login packet for
// mysql_native_password.
func buildHandshakeResponse41(user, database string, scramble []byte) []byte {
	caps := mysqlClientLongPassword | mysqlClientProtocol41 | mysqlClientTransactions |
		mysqlClientSecureConnection | mysqlClientPluginAuth
	if database != "" {
		caps |= mysqlClientConnectWithDB
	}

	var b []byte
	b = binary.LittleEndian.AppendUint32(b, caps)
	b = binary.LittleEndian.AppendUint32(b, 16*1024*1024) // max packet size
	b = append(b, 0x21)                                   // charset
	b = append(b, make([]byte, 23)...)                    // reserved
	b = append(b, []byte(user)...)
	b = append(b, 0x00) //nolint:gocritic // wire fields kept one-per-line: username NUL terminator
	b = append(b, byte(len(scramble)))
	b = append(b, scramble...)
	if database != "" {
		b = append(b, []byte(database)...)
		b = append(b, 0x00)
	}
	b = append(b, []byte(mysqlNativePassword)...)
	b = append(b, 0x00)
	return b
}

// scrambleNativePassword computes the mysql_native_password response:
// SHA1(password) XOR SHA1(salt || SHA1(SHA1(password))).
func scrambleNativePassword(password, salt []byte) []byte {
	if len(password) == 0 {
		return nil
	}
	h1 := sha1.Sum(password) //nolint:gosec // mandated by mysql_native_password
	h2 := sha1.Sum(h1[:])    //nolint:gosec
	h3 := sha1.New()         //nolint:gosec
	h3.Write(salt)
	h3.Write(h2[:])
	h3sum := h3.Sum(nil)
	out := make([]byte, 20)
	for i := 0; i < 20; i++ {
		out[i] = h1[i] ^ h3sum[i]
	}
	return out
}

// parseAuthSwitch extracts the plugin name and salt from an AuthSwitchRequest.
func parseAuthSwitch(pkt []byte) (plugin string, salt []byte) {
	if len(pkt) < 2 {
		return "", nil
	}
	body := pkt[1:]
	end := indexByte(body, 0x00)
	if end < 0 {
		return string(body), nil
	}
	plugin = string(body[:end])
	salt = trimTrailingNUL(body[end+1:])
	if len(salt) > 20 {
		salt = salt[:20]
	}
	return plugin, salt
}

// writeMySQLOK writes a minimal OK packet.
func writeMySQLOK(w io.Writer, seq byte) error {
	// 0x00, affected_rows=0 (lenenc), last_insert_id=0 (lenenc),
	// status_flags (autocommit), warnings=0.
	payload := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
	return writePacket(w, seq, payload)
}

// writeMySQLError writes an ERR packet (protocol-41 form with SQL state).
func writeMySQLError(w io.Writer, seq byte, code uint16, sqlState, msg string) {
	var b []byte
	b = append(b, 0xff)
	b = binary.LittleEndian.AppendUint16(b, code)
	b = append(b, '#')
	b = append(b, []byte(sqlState)...)
	b = append(b, []byte(msg)...)
	_ = writePacket(w, seq, b)
}

// mysqlErrText extracts the human-readable message from an ERR packet.
func mysqlErrText(pkt []byte) string {
	if len(pkt) < 9 {
		return "unknown error"
	}
	// 0xff + 2-byte code + '#' + 5-byte sqlstate + message.
	if pkt[3] == '#' {
		return string(pkt[9:])
	}
	return string(pkt[3:])
}

// trimTrailingNUL drops a single trailing NUL byte if present.
func trimTrailingNUL(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == 0x00 {
		return b[:n-1]
	}
	return b
}

// indexByte returns the index of c in b, or -1.
func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// firstByte returns b[0] or 0 for an empty slice.
func firstByte(b []byte) byte {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}
