package gateway

import (
	"bytes"
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

// RDP negotiation protocol identifiers ([MS-RDPBCGR] 2.2.1.1.1 / 2.2.1.2.1).
const (
	rdpNegProtocolRDP    uint32 = 0x00000000 // standard RDP security
	rdpNegProtocolSSL    uint32 = 0x00000001 // TLS
	rdpNegProtocolHybrid uint32 = 0x00000002 // CredSSP / NLA
)

// RDP negotiation message types.
const (
	rdpNegTypeReq uint8 = 0x01 // RDP_NEG_REQ
	rdpNegTypeRsp uint8 = 0x02 // RDP_NEG_RSP
)

// X.224 TPDU codes used by the proxy.
const (
	x224TPDUConnectionRequest uint8 = 0xE0
	x224TPDUConnectionConfirm uint8 = 0xD0
	x224TPDUData              uint8 = 0xF0
)

// MCS DomainMCSPDU choices (top 6 bits of the first PER byte).
const (
	mcsSendDataRequest    uint8 = 25 // 0x64 when shifted
	mcsSendDataIndication uint8 = 26 // 0x68 when shifted
)

// Security header flag indicating the PDU is the Client Info PDU
// ([MS-RDPBCGR] 2.2.8.1.1.2.1, SEC_INFO_PKT).
const secInfoPkt uint16 = 0x0040

// INFO_UNICODE flag in TS_INFO_PACKET flags: strings are UTF-16LE.
const infoUnicode uint32 = 0x00000010

// tpktHeaderLen is the fixed TPKT header size.
const tpktHeaderLen = 4

// maxTPKTLen bounds a single TPKT PDU the proxy will buffer.
const maxTPKTLen = 16 * 1024 * 1024

// rdpChannelDef is a virtual channel requested in CS_NET. Its server-assigned
// id is learned positionally from SC_NET during the relay (see forwardUpstream)
// rather than stored here.
type rdpChannelDef struct {
	name string
}

// RDPProxy is the gateway.ConnHandler for the RDP listener (:3389). It
// terminates the operator's RDP connection, extracts the one-shot connect token
// from the X.224 Connection Request routing cookie ("Cookie: mstshash=<token>"),
// redeems it, then dials the upstream RDP server with the security mode the
// target configures (standard RDP, TLS, or NLA/CredSSP). It injects the JIT vault
// credential into the Client Info PDU (TS_INFO_PACKET domain/username/password)
// and gates clipboard and drive redirection by dropping virtual-channel PDUs on
// the cliprdr/rdpdr channels when the policy engine denies them. The stream
// is recorded and the session open/close is appended to the workspace audit
// hash chain.
//
// Security mode (per-target "security" config: "rdp" (default), "tls" or "nla"):
//   - "rdp": standard RDP security on both hops; the operator and upstream PDUs
//     are plaintext and the vault credential is injected into the Client Info PDU.
//   - "tls": Enhanced RDP Security (TLS) terminated at the gateway on both hops.
//   - "nla": Enhanced RDP Security to the operator (TLS) and CredSSP/NLA to the
//     upstream — the gateway runs CredSSP as the client (see credssp.go),
//     authenticating to the upstream with the vault credential delivered as
//     TSCredentials, so modern Windows servers that require NLA work without a
//     downgrade. Because both hops then use Enhanced RDP Security, the relayed
//     MCS/GCC/Client Info PDUs carry no per-PDU RDP security header and map 1:1,
//     so credential injection and clipboard/drive gating operate unchanged on
//     the decrypted stream in the middle.
//
// In every mode the operator authenticates via the one-shot connect token in the
// X.224 routing cookie (read in clear text before any TLS upgrade), the stream is
// recorded, and session open/close is appended to the workspace audit hash chain.
type RDPProxy struct {
	broker      *pam.Broker
	sessions    *pam.SessionManager
	hub         *SessionHub
	store       ReplayStore
	dialTimeout time.Duration
	recMaxBytes int
	serverTLS   *tls.Config
}

// RDPProxyConfig configures an RDPProxy.
type RDPProxyConfig struct {
	Broker      *pam.Broker
	Sessions    *pam.SessionManager
	Hub         *SessionHub
	Store       ReplayStore
	DialTimeout time.Duration
	RecMaxBytes int
	// TLSConfig is the server-side TLS config presented to the operator when the
	// target uses Enhanced RDP Security ("tls"/"nla"). When nil an ephemeral
	// self-signed certificate is generated, matching the other proxies.
	TLSConfig *tls.Config
}

// NewRDPProxy builds an RDPProxy. broker and sessions are required.
func NewRDPProxy(cfg RDPProxyConfig) (*RDPProxy, error) {
	if cfg.Broker == nil || cfg.Sessions == nil {
		return nil, errors.New("gateway: RDPProxy requires broker and session manager")
	}
	dt := cfg.DialTimeout
	if dt <= 0 {
		dt = 15 * time.Second
	}
	tlsCfg := cfg.TLSConfig
	if tlsCfg == nil {
		cert, err := ephemeralTLSCert()
		if err != nil {
			return nil, fmt.Errorf("gateway: rdp ephemeral cert: %w", err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12} //nolint:gosec
	}
	return &RDPProxy{
		broker:      cfg.Broker,
		sessions:    cfg.Sessions,
		hub:         cfg.Hub,
		store:       cfg.Store,
		dialTimeout: dt,
		recMaxBytes: cfg.RecMaxBytes,
		serverTLS:   tlsCfg,
	}, nil
}

// Handle implements gateway.ConnHandler.
func (p *RDPProxy) Handle(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	clientAddr := conn.RemoteAddr().String()

	// X.224 Connection Request from the operator carries the token in its
	// mstshash routing cookie.
	crPDU, token, err := p.readOperatorConnectionRequest(conn)
	if err != nil {
		logger.Warnf(ctx, "rdp-proxy: operator connection request from %s: %v", clientAddr, err)
		return
	}

	leased, err := p.broker.RedeemConnectToken(ctx, token, clientAddr)
	if err != nil {
		logger.Warnf(ctx, "rdp-proxy: redeem from %s failed: %v", clientAddr, err)
		return
	}
	if leased.Target.Protocol != models.PAMProtocolRDP {
		reconcileOrphanSession(ctx, p.sessions, leased.Session, "rdp-proxy")
		return
	}
	session := leased.Session
	logger.Infof(ctx, "rdp-proxy: session %s opened for %s → %s", session.ID, session.Subject, leased.Target.Address)

	sessCtx, cancel := context.WithCancel(ctx)
	rec := NewIORecorder(sessCtx, session.ID.String(), p.recMaxBytes)
	defer cancel()
	if p.hub != nil {
		defer p.hub.Register(session.ID, session.WorkspaceID, session.Subject, rec, cancel)()
	}
	defer func() {
		flushCtx, fcancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer fcancel()
		if err := rec.Flush(flushCtx, p.store); err != nil {
			logger.Warnf(ctx, "rdp-proxy: flush replay %s: %v", session.ID, err)
		}
		if recording := rec.Recording(); recording.Stored {
			if err := p.sessions.RecordRecording(flushCtx, session, pam.RecordingRef{
				Key: recording.Key, SHA256: recording.SHA256, Bytes: recording.Bytes, Truncated: recording.Truncated,
			}); err != nil {
				logger.Warnf(ctx, "rdp-proxy: record recording evidence %s: %v", session.ID, err)
			}
		}
		if err := p.sessions.CloseSession(flushCtx, session.WorkspaceID, session.ID); err != nil {
			logger.Warnf(ctx, "rdp-proxy: close session %s: %v", session.ID, err)
		}
	}()

	mode := rdpSecurityMode(leased)

	// Answer the operator's X.224 negotiation and, for Enhanced RDP Security
	// modes, upgrade the operator hop to TLS. This must precede the upstream dial
	// so a failed operator negotiation never opens an upstream session.
	operator, err := p.negotiateOperator(ctx, conn, crPDU, mode)
	if err != nil {
		rec.Annotate(fmt.Sprintf("[operator negotiation failed: %v]", err))
		logger.Warnf(ctx, "rdp-proxy: operator negotiation from %s: %v", clientAddr, err)
		return
	}

	upstream, err := p.dialUpstream(sessCtx, leased, mode)
	if err != nil {
		rec.Annotate(fmt.Sprintf("[upstream connect failed: %v]", err))
		logger.Warnf(ctx, "rdp-proxy: upstream %s: %v", leased.Target.Address, err)
		return
	}
	defer func() { _ = upstream.Close() }()

	// Decide whether clipboard/drive redirection is permitted for this session
	// up front; the result gates virtual-channel PDUs during the relay.
	clipboardAllowed := p.clipboardAllowed(sessCtx, session)
	if !clipboardAllowed {
		rec.Annotate("[clipboard/drive redirection blocked by policy]")
	}

	p.splice(sessCtx, operator, upstream, leased, session, rec, cancel, clipboardAllowed)
}

// rdpSecurityMode resolves the per-target security mode from the target config.
// It accepts the explicit "security" key ("rdp"/"tls"/"nla") and the legacy
// boolean shortcuts "nla":"true" and "tls":"true". The default is standard RDP
// security.
func rdpSecurityMode(leased *pam.LeasedSession) string {
	cfg := decodeTargetConfig(leased.Target.Config)
	switch strings.ToLower(cfg["security"]) {
	case "nla", "hybrid", "credssp":
		return "nla"
	case "tls", "ssl":
		return "tls"
	case "rdp", "standard", "":
		// fall through to the boolean shortcuts
	default:
		// unknown value: treat as standard
	}
	if cfg["nla"] == "true" {
		return "nla"
	}
	if cfg["tls"] == "true" {
		return "tls"
	}
	return "rdp"
}

// negotiateOperator sends the operator's X.224 Connection Confirm selecting the
// security protocol for the chosen mode and, for the TLS-backed modes, upgrades
// the operator connection to a server-side TLS session terminated at the
// gateway. The returned net.Conn is the connection the relay reads/writes
// (plaintext socket for "rdp", *tls.Conn for "tls"/"nla").
func (p *RDPProxy) negotiateOperator(ctx context.Context, conn net.Conn, operatorCR []byte, mode string) (net.Conn, error) {
	switch mode {
	case "tls", "nla":
		// The operator must have offered SSL (Enhanced RDP Security). mstsc always
		// offers SSL alongside HYBRID, so selecting SSL is a valid response even
		// when the operator requested NLA; the gateway is the operator's trust
		// boundary and re-originates NLA toward the upstream itself.
		if !operatorRequestedProtocol(operatorCR, rdpNegProtocolSSL|rdpNegProtocolHybrid) {
			return nil, errors.New("operator did not offer TLS/NLA security")
		}
		if err := writeTPKT(conn, buildConnectionConfirm(rdpNegProtocolSSL)); err != nil {
			return nil, fmt.Errorf("send connection confirm: %w", err)
		}
		_ = conn.SetDeadline(time.Now().Add(p.dialTimeout))
		tlsConn := tls.Server(conn, p.serverTLS)
		hsCtx, hsCancel := context.WithTimeout(ctx, p.dialTimeout)
		err := tlsConn.HandshakeContext(hsCtx)
		hsCancel()
		if err != nil {
			return nil, fmt.Errorf("operator tls handshake: %w", err)
		}
		_ = conn.SetDeadline(time.Time{})
		return tlsConn, nil
	default: // "rdp"
		if err := writeTPKT(conn, buildConnectionConfirm(rdpNegProtocolRDP)); err != nil {
			return nil, fmt.Errorf("send connection confirm: %w", err)
		}
		return conn, nil
	}
}

// clipboardAllowed evaluates the synthetic "clipboard:redirect" command against
// the policy engine once per session and records the decision in the audit
// chain.
func (p *RDPProxy) clipboardAllowed(ctx context.Context, session *models.PAMSession) bool {
	decision, err := p.sessions.LogCommand(ctx, session, "clipboard:redirect")
	if err != nil {
		return false
	}
	return decision.Allowed()
}

// readOperatorConnectionRequest reads the operator's X.224 Connection Request
// and extracts the connect token from its "Cookie: mstshash=<token>" routing
// field. The full PDU is returned so the negotiation flags can be replayed to
// the upstream.
func (p *RDPProxy) readOperatorConnectionRequest(conn net.Conn) ([]byte, string, error) {
	_ = conn.SetReadDeadline(time.Now().Add(p.dialTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	pdu, err := readTPKT(conn)
	if err != nil {
		return nil, "", fmt.Errorf("read connection request: %w", err)
	}
	if len(pdu) < tpktHeaderLen+7 || pdu[tpktHeaderLen+1] != x224TPDUConnectionRequest {
		return nil, "", errors.New("not an X.224 Connection Request")
	}
	token, err := mstshashToken(pdu)
	if err != nil {
		return nil, "", err
	}
	return pdu, token, nil
}

// dialUpstream connects to the upstream RDP server and performs the X.224
// negotiation for the chosen security mode:
//   - "rdp": request standard RDP security; the Client Info PDU and channel data
//     stay in clear text for injection and gating.
//   - "tls": request SSL; complete a TLS client handshake, then relay over TLS.
//   - "nla": request HYBRID (CredSSP); complete TLS, then run the CredSSP/NLA
//     client exchange (credssp.go) delivering the vault credential as
//     TSCredentials before relaying over TLS.
func (p *RDPProxy) dialUpstream(ctx context.Context, leased *pam.LeasedSession, mode string) (net.Conn, error) {
	d := net.Dialer{Timeout: p.dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", leased.Target.Address)
	if err != nil {
		return nil, fmt.Errorf("dial rdp: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(p.dialTimeout))

	requested := rdpNegProtocolRDP
	switch mode {
	case "nla":
		requested = rdpNegProtocolHybrid
	case "tls":
		requested = rdpNegProtocolSSL
	}

	user := credUser(leased)
	// Build our own Connection Request: replay the mstshash as the vault user and
	// request the negotiated security protocol.
	if err := writeTPKT(conn, buildConnectionRequest(user, requested)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("send connection request: %w", err)
	}
	cc, err := readTPKT(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read connection confirm: %w", err)
	}
	selected, err := selectedProtocol(cc)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	if mode == "rdp" {
		if selected != rdpNegProtocolRDP {
			_ = conn.Close()
			return nil, fmt.Errorf("upstream requires non-standard security (selected protocol %d); set the target's \"security\" to \"tls\" or \"nla\"", selected)
		}
		_ = conn.SetDeadline(time.Time{})
		return conn, nil
	}

	// Enhanced RDP Security: the upstream must have selected SSL or HYBRID.
	if selected != rdpNegProtocolSSL && selected != rdpNegProtocolHybrid {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream selected protocol %d, expected TLS/NLA", selected)
	}
	tlsConn := tls.Client(conn, upstreamRDPTLSConfig(leased))
	hsCtx, hsCancel := context.WithTimeout(ctx, p.dialTimeout)
	err = tlsConn.HandshakeContext(hsCtx)
	hsCancel()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream tls handshake: %w", err)
	}

	// CredSSP/NLA: authenticate with the vault credential and deliver it as
	// TSCredentials, binding to the server's TLS public key to defeat MITM.
	if mode == "nla" || selected == rdpNegProtocolHybrid {
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			_ = tlsConn.Close()
			return nil, errors.New("upstream presented no TLS certificate for CredSSP binding")
		}
		pubKeyInfo := state.PeerCertificates[0].RawSubjectPublicKeyInfo
		domain := decodeTargetConfig(leased.Target.Config)["domain"]
		if err := credsspClientAuth(tlsConn, pubKeyInfo, user, leased.Secret.Password, domain); err != nil {
			_ = tlsConn.Close()
			return nil, fmt.Errorf("upstream credssp/nla: %w", err)
		}
	}
	_ = conn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// upstreamRDPTLSConfig builds the TLS client config for the upstream RDP hop. A
// "ca_cert" PEM in the target config pins the upstream identity; otherwise chain
// verification is skipped because RDP servers typically present self-signed
// certificates and CredSSP's public-key binding (not PKI) is what protects the
// credential from a MITM.
func upstreamRDPTLSConfig(leased *pam.LeasedSession) *tls.Config {
	cfg := decodeTargetConfig(leased.Target.Config)
	host := leased.Target.Address
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if ca := cfg["ca_cert"]; ca != "" {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM([]byte(ca)) {
			tlsCfg.RootCAs = pool
			return tlsCfg
		}
	}
	tlsCfg.InsecureSkipVerify = true //nolint:gosec // no CA pinned: CredSSP public-key binding protects the credential; the gateway is the audited trust boundary to the upstream.
	return tlsCfg
}

// splice relays the post-negotiation RDP stream. The operator's Connection
// Confirm and any TLS upgrade have already happened in negotiateOperator; both
// directions are proxied TPKT-framed: operator→upstream PDUs are inspected so
// the Client Info PDU can have the vault credential injected and clipboard/drive
// channel PDUs can be dropped when policy denies; upstream→operator is recorded
// and copied through.
func (p *RDPProxy) splice(ctx context.Context, operator, upstream net.Conn, leased *pam.LeasedSession, session *models.PAMSession, rec *IORecorder, cancel context.CancelFunc, clipboardAllowed bool) {
	st := &rdpRelayState{
		leased:           leased,
		clipboardAllowed: clipboardAllowed,
		gatedChannels:    map[uint16]string{},
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		p.forwardOperator(ctx, operator, upstream, session, rec, st)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		p.forwardUpstream(ctx, operator, upstream, rec, st)
	}()
	go func() {
		<-ctx.Done()
		_ = operator.Close()
		_ = upstream.Close()
	}()
	wg.Wait()
}

// rdpRelayState carries the channel mapping learned during the GCC exchange and
// the per-session clipboard decision between the two relay directions.
type rdpRelayState struct {
	leased           *pam.LeasedSession
	clipboardAllowed bool

	mu            sync.Mutex
	channels      []rdpChannelDef // client channel names in CS_NET order
	gatedChannels map[uint16]string
	clientNetSeen bool
}

// forwardOperator relays operator→upstream PDUs, injecting the vault credential
// into the Client Info PDU and dropping gated virtual-channel PDUs.
func (p *RDPProxy) forwardOperator(ctx context.Context, operator, upstream net.Conn, session *models.PAMSession, rec *IORecorder, st *rdpRelayState) {
	for {
		// Honour the live soft-pause gate before reading the next operator
		// PDU: while an admin has frozen the session no further input PDU is
		// pulled or forwarded to the upstream RDP server.
		rec.WaitWhilePaused()
		pdu, err := readTPKT(operator)
		if err != nil {
			return
		}
		// MCS Connect Initial carries the client channel list (CS_NET). Learn the
		// channel order once so the server-assigned ids from SC_NET can be mapped.
		// CS_NET only appears in the Connect Initial; parseClientNetworkData walks
		// the GCC block structure (it does not scan for a marker), so steady-state
		// traffic won't match, but the seen-guard still avoids re-walking.
		st.mu.Lock()
		alreadySeen := st.clientNetSeen
		st.mu.Unlock()
		if !alreadySeen {
			if names, ok := parseClientNetworkData(pdu); ok {
				st.mu.Lock()
				st.channels = names
				st.clientNetSeen = true
				st.mu.Unlock()
			}
		}

		channelID, userData, sendDataOK := parseSendData(pdu, mcsSendDataRequest)
		if sendDataOK {
			// Gate clipboard/drive channels.
			if !st.clipboardAllowed {
				st.mu.Lock()
				name, gated := st.gatedChannels[channelID]
				st.mu.Unlock()
				if gated {
					rec.Annotate(fmt.Sprintf("[dropped %s channel PDU: clipboard/drive redirection denied]", name))
					continue
				}
			}
			// Inject credentials into the Client Info PDU.
			if isClientInfoPDU(userData) {
				newPDU, err := injectClientInfoCredentials(pdu, userData, st.leased)
				if err != nil {
					rec.Annotate(fmt.Sprintf("[client-info credential injection failed: %v]", err))
				} else {
					pdu = newPDU
					rec.Record(DirInput, []byte("[client-info PDU: injected vault credential]\n"))
				}
			}
		}
		rec.Record(DirInput, summarizePDU(pdu))
		if _, err := upstream.Write(pdu); err != nil {
			return
		}
	}
}

// forwardUpstream relays upstream→operator PDUs, learning the server channel id
// assignments (SC_NET) so clipboard/drive channels can be gated by id.
func (p *RDPProxy) forwardUpstream(ctx context.Context, operator, upstream net.Conn, rec *IORecorder, st *rdpRelayState) {
	for {
		pdu, err := readTPKT(upstream)
		if err != nil {
			return
		}
		if ids, ok := parseServerNetworkData(pdu); ok {
			st.mu.Lock()
			for i, id := range ids {
				if i < len(st.channels) {
					nm := strings.ToLower(st.channels[i].name)
					if nm == "cliprdr" || nm == "rdpdr" || nm == "drdynvc" {
						st.gatedChannels[id] = st.channels[i].name
					}
				}
			}
			st.mu.Unlock()
		}
		rec.Record(DirOutput, summarizePDU(pdu))
		if _, err := operator.Write(pdu); err != nil {
			return
		}
	}
}

// --- TPKT / X.224 helpers -------------------------------------------------

// readTPKT reads one TPKT-encapsulated PDU (version 3) in full.
func readTPKT(r io.Reader) ([]byte, error) {
	var hdr [tpktHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0x03 {
		return nil, fmt.Errorf("unexpected TPKT version 0x%02x", hdr[0])
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]))
	if length < tpktHeaderLen || length > maxTPKTLen {
		return nil, fmt.Errorf("invalid TPKT length %d", length)
	}
	buf := make([]byte, length)
	copy(buf, hdr[:])
	if _, err := io.ReadFull(r, buf[tpktHeaderLen:]); err != nil {
		return nil, err
	}
	return buf, nil
}

// writeTPKT writes a complete TPKT PDU (the caller supplies the bytes after the
// TPKT header) by prepending a version-3 header.
func writeTPKT(w io.Writer, x224 []byte) error {
	total := tpktHeaderLen + len(x224)
	if total > maxTPKTLen {
		return fmt.Errorf("TPKT PDU too large (%d bytes)", total)
	}
	frame := make([]byte, total)
	frame[0] = 0x03
	frame[1] = 0x00
	binary.BigEndian.PutUint16(frame[2:4], uint16(total))
	copy(frame[tpktHeaderLen:], x224)
	_, err := w.Write(frame)
	return err
}

// mstshashToken extracts the token from the "Cookie: mstshash=<token>\r\n"
// routing field of an X.224 Connection Request PDU.
func mstshashToken(pdu []byte) (string, error) {
	const marker = "Cookie: mstshash="
	idx := bytes.Index(pdu, []byte(marker))
	if idx < 0 {
		return "", errors.New("connection request missing mstshash cookie")
	}
	rest := pdu[idx+len(marker):]
	end := bytes.IndexByte(rest, '\r')
	if end < 0 {
		end = bytes.IndexByte(rest, '\n')
	}
	if end < 0 {
		return "", errors.New("malformed mstshash cookie (no terminator)")
	}
	token := strings.TrimSpace(string(rest[:end]))
	if token == "" {
		return "", errors.New("empty mstshash token")
	}
	return token, nil
}

// buildConnectionRequest builds an X.224 Connection Request (the bytes after
// the TPKT header) carrying a mstshash cookie and an RDP_NEG_REQ requesting the
// given protocol.
func buildConnectionRequest(user string, requestedProtocol uint32) []byte {
	cookie := []byte(fmt.Sprintf("Cookie: mstshash=%s\r\n", user))
	// RDP_NEG_REQ: type(1) flags(1) length(2 LE)=8 requestedProtocols(4 LE).
	neg := make([]byte, 8)
	neg[0] = rdpNegTypeReq
	neg[1] = 0x00
	binary.LittleEndian.PutUint16(neg[2:4], 8)
	binary.LittleEndian.PutUint32(neg[4:8], requestedProtocol)

	// X.224 CR header: length indicator(1), CR code(1)=0xE0, dst-ref(2),
	// src-ref(2), class(1). The length indicator counts every byte after itself.
	variable := append(append([]byte{}, cookie...), neg...)
	li := 6 + len(variable) // CR code + dstref + srcref + class + variable
	hdr := []byte{byte(li), x224TPDUConnectionRequest, 0x00, 0x00, 0x00, 0x00, 0x00}
	return append(hdr, variable...)
}

// buildConnectionConfirm builds an X.224 Connection Confirm (bytes after the
// TPKT header) carrying an RDP_NEG_RSP selecting the given protocol.
func buildConnectionConfirm(selectedProtocol uint32) []byte {
	neg := make([]byte, 8)
	neg[0] = rdpNegTypeRsp
	neg[1] = 0x00
	binary.LittleEndian.PutUint16(neg[2:4], 8)
	binary.LittleEndian.PutUint32(neg[4:8], selectedProtocol)

	li := 6 + len(neg)
	hdr := []byte{byte(li), x224TPDUConnectionConfirm, 0x00, 0x00, 0x00, 0x00, 0x00}
	return append(hdr, neg...)
}

// selectedProtocol reads the selectedProtocol field from a Connection Confirm's
// RDP_NEG_RSP. A Confirm with no negotiation structure means the server fell
// back to standard RDP security.
func selectedProtocol(pdu []byte) (uint32, error) {
	if len(pdu) < tpktHeaderLen+2 || pdu[tpktHeaderLen+1] != x224TPDUConnectionConfirm {
		return 0, errors.New("not an X.224 Connection Confirm")
	}
	// X.224 header is 7 bytes after the TPKT header; the RDP_NEG_RSP (if any)
	// follows.
	negOff := tpktHeaderLen + 7
	if len(pdu) < negOff+8 {
		return rdpNegProtocolRDP, nil
	}
	if pdu[negOff] != rdpNegTypeRsp {
		return rdpNegProtocolRDP, nil
	}
	return binary.LittleEndian.Uint32(pdu[negOff+4 : negOff+8]), nil
}

// operatorRequestedProtocol reports whether the operator's X.224 Connection
// Request advertised any of the protocols in mask via its RDP_NEG_REQ
// ([MS-RDPBCGR] 2.2.1.1.1). An absent RDP_NEG_REQ means standard RDP only.
func operatorRequestedProtocol(cr []byte, mask uint32) bool {
	const x224HeaderLen = 7
	p := tpktHeaderLen + x224HeaderLen
	if len(cr) < p {
		return false
	}
	rest := cr[p:]
	// Skip an optional routing cookie line ("Cookie: mstshash=...\r\n").
	if bytes.HasPrefix(rest, []byte("Cookie:")) || bytes.HasPrefix(rest, []byte("mstshash")) {
		if i := bytes.Index(rest, []byte("\r\n")); i >= 0 {
			rest = rest[i+2:]
		}
	}
	if len(rest) < 8 || rest[0] != rdpNegTypeReq {
		return false
	}
	return binary.LittleEndian.Uint32(rest[4:8])&mask != 0
}

// --- MCS / GCC helpers ----------------------------------------------------

// parseSendData parses an MCS Send Data Request/Indication PDU embedded in a
// TPKT/X.224 data PDU, returning the channel id and the user-data payload. The
// boolean is false when the PDU is not the requested Send Data type.
func parseSendData(pdu []byte, want uint8) (channelID uint16, userData []byte, ok bool) {
	// TPKT(4) + X.224 data header(3: length-indicator, 0xF0, EOT) → MCS.
	off := tpktHeaderLen + 3
	if len(pdu) < off+1 {
		return 0, nil, false
	}
	if len(pdu) < tpktHeaderLen+2 || pdu[tpktHeaderLen+1] != x224TPDUData {
		return 0, nil, false
	}
	choice := pdu[off] >> 2
	if uint8(choice) != want {
		return 0, nil, false
	}
	// SendData: initiator(2) channelId(2) dataPriority(1) length(PER) userData.
	p := off + 1
	if len(pdu) < p+5 {
		return 0, nil, false
	}
	channelID = binary.BigEndian.Uint16(pdu[p+2 : p+4])
	p += 5 // initiator(2) + channelId(2) + dataPriority(1)
	n, consumed, lerr := perReadLength(pdu[p:])
	if lerr != nil {
		return 0, nil, false
	}
	p += consumed
	if p+n > len(pdu) {
		return 0, nil, false
	}
	return channelID, pdu[p : p+n], true
}

// sendDataUserDataOffset returns the byte offset within pdu where the Send Data
// user-data payload begins, or -1 if pdu is not a Send Data PDU. Used to splice
// a rewritten user-data payload back into a PDU.
func sendDataUserDataOffset(pdu []byte, want uint8) int {
	off := tpktHeaderLen + 3
	if len(pdu) < off+1 || pdu[tpktHeaderLen+1] != x224TPDUData {
		return -1
	}
	if uint8(pdu[off]>>2) != want {
		return -1
	}
	p := off + 1 + 5
	_, consumed, err := perReadLength(pdu[p:])
	if err != nil {
		return -1
	}
	return p + consumed
}

// perReadLength decodes a PER length determinant (the form RDP uses for Send
// Data user-data lengths): one byte if < 0x80, otherwise a 2-byte big-endian
// value with the top bit of the first byte set.
func perReadLength(b []byte) (length, consumed int, err error) {
	if len(b) < 1 {
		return 0, 0, errors.New("per length: empty")
	}
	if b[0]&0x80 == 0 {
		return int(b[0]), 1, nil
	}
	if len(b) < 2 {
		return 0, 0, errors.New("per length: truncated 2-byte form")
	}
	return int(b[0]&0x7f)<<8 | int(b[1]), 2, nil
}

// perWriteLength encodes a PER length determinant matching perReadLength.
func perWriteLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	return []byte{0x80 | byte(n>>8), byte(n)}
}

// isClientInfoPDU reports whether a Send Data user-data payload is the Client
// Info PDU, detected via the SEC_INFO_PKT flag in the leading Security Header.
func isClientInfoPDU(userData []byte) bool {
	if len(userData) < 4 {
		return false
	}
	flags := binary.LittleEndian.Uint16(userData[0:2])
	return flags&secInfoPkt != 0
}

// injectClientInfoCredentials rewrites the Domain, UserName and Password fields
// of the TS_INFO_PACKET inside a Client Info PDU with the leased vault
// credential, fixing up the TPKT and MCS length fields. Only the UNICODE form
// is supported (every modern RDP client sets INFO_UNICODE).
func injectClientInfoCredentials(pdu, userData []byte, leased *pam.LeasedSession) ([]byte, error) {
	udOff := sendDataUserDataOffset(pdu, mcsSendDataRequest)
	if udOff < 0 {
		return nil, errors.New("not a send-data PDU")
	}
	// TS_INFO_PACKET begins after the 4-byte Security Header.
	const secHdr = 4
	if len(userData) < secHdr+18 {
		return nil, errors.New("client info PDU too short")
	}
	info := userData[secHdr:]
	flags := binary.LittleEndian.Uint32(info[4:8])
	if flags&infoUnicode == 0 {
		return nil, errors.New("non-unicode Client Info PDU not supported")
	}
	cbDomain := int(binary.LittleEndian.Uint16(info[8:10]))
	cbUser := int(binary.LittleEndian.Uint16(info[10:12]))
	cbPass := int(binary.LittleEndian.Uint16(info[12:14]))
	cbShell := int(binary.LittleEndian.Uint16(info[14:16]))
	cbWorkDir := int(binary.LittleEndian.Uint16(info[16:18]))

	// Fixed header is 18 bytes (CodePage..cbWorkingDir); the variable strings
	// follow, each NUL-terminated (the cb* counts exclude the 2-byte terminator).
	const fixed = 18
	domEnd := fixed + cbDomain + 2
	userEnd := domEnd + cbUser + 2
	passEnd := userEnd + cbPass + 2
	if passEnd > len(info) {
		return nil, errors.New("client info PDU truncated before password end")
	}
	_, _ = cbShell, cbWorkDir // shell/workingdir live in the preserved tail

	newDomain := utf16zTerminated(decodeTargetConfig(leased.Target.Config)["domain"])
	newUser := utf16zTerminated(credUser(leased))
	newPass := utf16zTerminated(leased.Secret.Password)

	// Rebuild TS_INFO_PACKET: fixed header (with updated cb fields) + new
	// domain/user/password + the original tail (alternate shell, working dir,
	// extended info) that followed the password.
	nb := append([]byte{}, info[:fixed]...)
	binary.LittleEndian.PutUint16(nb[8:10], uint16(len(newDomain)-2))
	binary.LittleEndian.PutUint16(nb[10:12], uint16(len(newUser)-2))
	binary.LittleEndian.PutUint16(nb[12:14], uint16(len(newPass)-2))
	nb = append(nb, newDomain...)
	nb = append(nb, newUser...)
	nb = append(nb, newPass...)
	nb = append(nb, info[passEnd:]...)

	newUserData := append(append([]byte{}, userData[:secHdr]...), nb...)

	// Rebuild the PDU from the PER length determinant onward with a freshly
	// encoded length and the new user data. The determinant sits at a fixed
	// offset in a Send Data PDU — TPKT(4) + X.224 data header(3) + MCS choice(1)
	// + initiator(2) + channelID(2) + dataPriority(1) — which is exactly where
	// sendDataUserDataOffset reads it. Deriving the start from that layout is
	// correct even when a 2-byte length's low byte has bit 7 clear (user-data
	// lengths like 256–383): the old heuristic that inspected the byte just
	// before udOff misread those as a 1-byte determinant and corrupted the PDU.
	lenFieldStart := tpktHeaderLen + 3 + 1 + 5
	out := append([]byte{}, pdu[:lenFieldStart]...)
	out = append(out, perWriteLength(len(newUserData))...)
	out = append(out, newUserData...)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out))) // fix TPKT total length
	return out, nil
}

// h221ClientKey and h221ServerKey are the H.221 non-standard keys that delimit
// the settings user data inside the GCC Conference Create Request (client) and
// Response (server) carried by the MCS Connect Initial/Response PDUs
// ([MS-RDPBCGR] 2.2.1.3 / 2.2.1.4). The settings blocks (CS_*/SC_*) immediately
// follow the key and a PER-encoded user-data length.
var (
	h221ClientKey = []byte("Duca")
	h221ServerKey = []byte("McDn")
)

const (
	gccTypeClientNetwork uint16 = 0xC003 // CS_NET
	gccTypeServerNetwork uint16 = 0x0C03 // SC_NET
)

// gccBlock locates the GCC settings block of type want inside an MCS Connect
// Initial/Response PDU. Instead of scanning the whole PDU for the 2-byte block
// type — which can false-match those bytes appearing inside another block's
// payload (e.g. a desktop name or certificate) — it anchors on the 4-byte H.221
// key that delimits the settings user data, then walks the length-prefixed
// block list, only ever reading a block-type field at a real block boundary.
// It returns the block including its 4-byte (type, length) header and fails
// closed on any framing inconsistency.
func gccBlock(pdu, h221Key []byte, want uint16) ([]byte, bool) {
	keyIdx := bytes.Index(pdu, h221Key)
	if keyIdx < 0 {
		return nil, false
	}
	p := keyIdx + len(h221Key)
	udLen, consumed, err := perReadLength(pdu[p:])
	if err != nil {
		return nil, false
	}
	p += consumed
	end := p + udLen
	if end > len(pdu) {
		return nil, false
	}
	for p+4 <= end {
		blockType := binary.LittleEndian.Uint16(pdu[p : p+2])
		blockLen := int(binary.LittleEndian.Uint16(pdu[p+2 : p+4]))
		if blockLen < 4 || p+blockLen > end {
			return nil, false
		}
		if blockType == want {
			return pdu[p : p+blockLen], true
		}
		p += blockLen
	}
	return nil, false
}

// parseClientNetworkData locates the CS_NET block inside an MCS Connect Initial
// PDU's GCC user data and returns the requested channel definitions in order.
// ok is false when the PDU contains no CS_NET block.
func parseClientNetworkData(pdu []byte) ([]rdpChannelDef, bool) {
	block, ok := gccBlock(pdu, h221ClientKey, gccTypeClientNetwork)
	if !ok || len(block) < 8 {
		return nil, false
	}
	// TS_UD_CS_NET: header(4), channelCount(4), channelDefArray(count×12).
	count := int(binary.LittleEndian.Uint32(block[4:8]))
	p := 8
	var defs []rdpChannelDef
	for i := 0; i < count; i++ {
		if p+12 > len(block) {
			break
		}
		name := string(bytes.TrimRight(block[p:p+8], "\x00"))
		defs = append(defs, rdpChannelDef{name: name})
		p += 12 // 8-byte name + 4-byte options
	}
	return defs, len(defs) > 0
}

// parseServerNetworkData locates the SC_NET block inside an MCS Connect Response
// PDU's GCC user data and returns the server-assigned channel ids in order. ok
// is false when the PDU contains no SC_NET block.
func parseServerNetworkData(pdu []byte) ([]uint16, bool) {
	block, ok := gccBlock(pdu, h221ServerKey, gccTypeServerNetwork)
	if !ok || len(block) < 8 {
		return nil, false
	}
	// TS_UD_SC_NET: header(4), MCSChannelId(2), channelCount(2), idArray(count×2).
	channelCount := int(binary.LittleEndian.Uint16(block[6:8]))
	p := 8
	var ids []uint16
	for i := 0; i < channelCount; i++ {
		if p+2 > len(block) {
			break
		}
		ids = append(ids, binary.LittleEndian.Uint16(block[p:p+2]))
		p += 2
	}
	return ids, len(ids) > 0
}

// summarizePDU renders a short, fixed-size record line for a relayed PDU so the
// session transcript captures activity without storing full frame buffers.
func summarizePDU(pdu []byte) []byte {
	return []byte(fmt.Sprintf("[rdp pdu %d bytes]\n", len(pdu)))
}

// utf16zTerminated encodes s as UTF-16LE with a trailing NUL code unit.
func utf16zTerminated(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, len(u)*2+2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(out[i*2:], r)
	}
	return out
}
