package gateway

import (
	"context"
	"crypto/des" //nolint:gosec // RFB/VNC authentication mandates DES; this is wire-protocol interop, not a security-primitive choice.
	"crypto/rand"
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

// RFB security types used by the proxy.
const (
	rfbSecVNCAuth  uint8 = 2  // upstream authentication (DES challenge-response)
	rfbSecVeNCrypt uint8 = 19 // operator authentication (carries the token via Plain)
)

// VeNCrypt Plain sub-type: username/password in clear (the operator presents the
// connect token as the password).
const veNCryptPlain uint32 = 256

// RFB client→server message types the proxy must recognise to frame the stream
// and gate clipboard pastes. The first group is the RFC 6143 core set; the
// second group is the widely-deployed extension messages (TigerVNC, UltraVNC,
// QEMU) the proxy frames so legitimate clients are not severed while clipboard
// gating stays intact.
const (
	rfbCMsgSetPixelFormat           uint8 = 0
	rfbCMsgSetEncodings             uint8 = 2
	rfbCMsgFramebufferUpdateRequest uint8 = 3
	rfbCMsgKeyEvent                 uint8 = 4
	rfbCMsgPointerEvent             uint8 = 5
	rfbCMsgClientCutText            uint8 = 6

	rfbCMsgEnableContinuousUpdates uint8 = 150 // EnableContinuousUpdates
	rfbCMsgClientFence             uint8 = 248 // ClientFence
	rfbCMsgXvp                     uint8 = 250 // xvp
	rfbCMsgSetDesktopSize          uint8 = 251 // SetDesktopSize
	rfbCMsgQEMU                    uint8 = 255 // QEMU Client Message
)

// QEMU Client Message (type 255) sub-message types ([QEMU RFB extensions]).
const (
	qemuSubExtendedKeyEvent uint8 = 0
	qemuSubAudio            uint8 = 1
)

// qemuAudioSetFormat is the QEMU audio operation that carries a 4-byte format
// trailer (sample-format, channels, frequency); the enable/disable operations
// carry no trailer.
const qemuAudioSetFormat uint16 = 2

// maxRFBFenceLen bounds a ClientFence payload (the wire field is a single byte,
// so 255 is the protocol maximum).
const maxRFBFenceLen = 255

// maxRFBScreens bounds the SetDesktopSize screen count to keep the per-screen
// (16 bytes each) read bounded against a hostile operator.
const maxRFBScreens = 1024

// rfbProtocolVersion is the version the proxy speaks on both hops.
const rfbProtocolVersion = "RFB 003.008\n"

// maxRFBCutTextLen bounds a ClientCutText payload the proxy will buffer while
// gating it, preventing an unbounded allocation from a hostile operator.
const maxRFBCutTextLen = 4 * 1024 * 1024

// VNCProxy is the gateway.ConnHandler for the VNC listener (:5900). It presents
// itself to the operator as an RFB 3.8 server offering VeNCrypt Plain, through
// which the operator's client sends the one-shot connect token as the password.
// After redeeming the token it dials the upstream VNC server and authenticates
// as the gateway using VNC Authentication (DES challenge-response) with the
// JIT-injected vault password, bridges the ClientInit/ServerInit exchange, then
// relays the RFB stream with frame-buffer recording. ClientCutText (clipboard
// paste) messages are gated against the 1C policy engine and dropped when
// denied. Session open/close lands in the workspace audit hash chain.
type VNCProxy struct {
	broker      *pam.Broker
	sessions    *pam.SessionManager
	hub         *SessionHub
	store       ReplayStore
	dialTimeout time.Duration
	recMaxBytes int
}

// VNCProxyConfig configures a VNCProxy.
type VNCProxyConfig struct {
	Broker      *pam.Broker
	Sessions    *pam.SessionManager
	Hub         *SessionHub
	Store       ReplayStore
	DialTimeout time.Duration
	RecMaxBytes int
}

// NewVNCProxy builds a VNCProxy. broker and sessions are required.
func NewVNCProxy(cfg VNCProxyConfig) (*VNCProxy, error) {
	if cfg.Broker == nil || cfg.Sessions == nil {
		return nil, errors.New("gateway: VNCProxy requires broker and session manager")
	}
	dt := cfg.DialTimeout
	if dt <= 0 {
		dt = 15 * time.Second
	}
	return &VNCProxy{
		broker:      cfg.Broker,
		sessions:    cfg.Sessions,
		hub:         cfg.Hub,
		store:       cfg.Store,
		dialTimeout: dt,
		recMaxBytes: cfg.RecMaxBytes,
	}, nil
}

// Handle implements gateway.ConnHandler.
func (p *VNCProxy) Handle(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	clientAddr := conn.RemoteAddr().String()

	token, err := p.authenticateOperator(ctx, conn)
	if err != nil {
		logger.Warnf(ctx, "vnc-proxy: operator auth from %s: %v", clientAddr, err)
		return
	}

	leased, err := p.broker.RedeemConnectToken(ctx, token, clientAddr)
	if err != nil {
		_ = writeVNCSecurityResult(conn, false, "connect token rejected")
		logger.Warnf(ctx, "vnc-proxy: redeem from %s failed: %v", clientAddr, err)
		return
	}
	if leased.Target.Protocol != models.PAMProtocolVNC {
		_ = writeVNCSecurityResult(conn, false, "token is not for a vnc target")
		reconcileOrphanSession(ctx, p.sessions, leased.Session, "vnc-proxy")
		return
	}
	session := leased.Session
	logger.Infof(ctx, "vnc-proxy: session %s opened for %s → %s", session.ID, session.Subject, leased.Target.Address)

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
			logger.Warnf(ctx, "vnc-proxy: flush replay %s: %v", session.ID, err)
		}
		if err := p.sessions.CloseSession(flushCtx, session.WorkspaceID, session.ID); err != nil {
			logger.Warnf(ctx, "vnc-proxy: close session %s: %v", session.ID, err)
		}
	}()

	upstream, err := p.dialUpstream(sessCtx, leased)
	if err != nil {
		_ = writeVNCSecurityResult(conn, false, "upstream connection failed")
		rec.Annotate(fmt.Sprintf("[upstream connect failed: %v]", err))
		logger.Warnf(ctx, "vnc-proxy: upstream %s: %v", leased.Target.Address, err)
		return
	}
	defer func() { _ = upstream.Close() }()

	// Operator auth and upstream auth both succeeded; tell the operator and then
	// bridge the ClientInit/ServerInit exchange in correct RFB order:
	// SecurityResult → ClientInit → ServerInit.
	if err := writeVNCSecurityResult(conn, true, ""); err != nil {
		logger.Warnf(ctx, "vnc-proxy: send operator security result: %v", err)
		return
	}
	serverInit, err := p.bridgeInit(conn, upstream)
	if err != nil {
		rec.Annotate(fmt.Sprintf("[init bridge failed: %v]", err))
		logger.Warnf(ctx, "vnc-proxy: init bridge: %v", err)
		return
	}
	rec.Record(DirOutput, serverInit)

	p.splice(sessCtx, conn, upstream, session, rec, cancel)
}

// authenticateOperator runs the gateway's RFB server handshake with the
// operator: ProtocolVersion exchange, offer VeNCrypt, negotiate the Plain
// sub-type, and read the username/password where the password is the connect
// token. ClientInit is NOT read here — RFB requires it to follow SecurityResult,
// which the gateway only sends after the token is redeemed (see bridgeInit).
func (p *VNCProxy) authenticateOperator(ctx context.Context, conn net.Conn) (token string, err error) {
	_ = ctx
	_ = conn.SetReadDeadline(time.Now().Add(p.dialTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	if _, err := conn.Write([]byte(rfbProtocolVersion)); err != nil {
		return "", fmt.Errorf("send protocol version: %w", err)
	}
	var ver [12]byte
	if _, err := io.ReadFull(conn, ver[:]); err != nil {
		return "", fmt.Errorf("read operator version: %w", err)
	}

	// Offer exactly VeNCrypt.
	if _, err := conn.Write([]byte{0x01, rfbSecVeNCrypt}); err != nil {
		return "", fmt.Errorf("send security types: %w", err)
	}
	var pick [1]byte
	if _, err := io.ReadFull(conn, pick[:]); err != nil {
		return "", fmt.Errorf("read security pick: %w", err)
	}
	if pick[0] != rfbSecVeNCrypt {
		return "", fmt.Errorf("operator selected unsupported security type %d", pick[0])
	}

	// VeNCrypt version handshake (server 0.2).
	if _, err := conn.Write([]byte{0x00, 0x02}); err != nil {
		return "", err
	}
	var cliVer [2]byte
	if _, err := io.ReadFull(conn, cliVer[:]); err != nil {
		return "", fmt.Errorf("read vencrypt version: %w", err)
	}
	if cliVer[0] != 0x00 || cliVer[1] != 0x02 {
		_, _ = conn.Write([]byte{0x01}) // version not supported
		return "", fmt.Errorf("unsupported VeNCrypt version %d.%d", cliVer[0], cliVer[1])
	}
	if _, err := conn.Write([]byte{0x00}); err != nil { // version OK
		return "", err
	}

	// Offer exactly the Plain sub-type.
	sub := make([]byte, 1+4)
	sub[0] = 0x01
	binary.BigEndian.PutUint32(sub[1:], veNCryptPlain)
	if _, err := conn.Write(sub); err != nil {
		return "", err
	}
	var chosen [4]byte
	if _, err := io.ReadFull(conn, chosen[:]); err != nil {
		return "", fmt.Errorf("read vencrypt subtype: %w", err)
	}
	if binary.BigEndian.Uint32(chosen[:]) != veNCryptPlain {
		return "", fmt.Errorf("operator selected unsupported VeNCrypt subtype %d", binary.BigEndian.Uint32(chosen[:]))
	}

	// Plain: uint32 userLen, uint32 passLen, user, pass.
	var lens [8]byte
	if _, err := io.ReadFull(conn, lens[:]); err != nil {
		return "", fmt.Errorf("read plain lengths: %w", err)
	}
	userLen := binary.BigEndian.Uint32(lens[0:4])
	passLen := binary.BigEndian.Uint32(lens[4:8])
	if userLen > 1024 || passLen == 0 || passLen > 4096 {
		return "", fmt.Errorf("implausible plain credential lengths (user=%d pass=%d)", userLen, passLen)
	}
	creds := make([]byte, userLen+passLen)
	if _, err := io.ReadFull(conn, creds); err != nil {
		return "", fmt.Errorf("read plain credentials: %w", err)
	}
	return string(creds[userLen:]), nil
}

// bridgeInit relays the ClientInit/ServerInit exchange after both hops have
// authenticated: it reads the operator's ClientInit shared flag, forwards it as
// the gateway's ClientInit to the upstream, and returns the upstream's
// ServerInit (also written to the operator). RFB requires SecurityResult to
// precede ClientInit, so this runs after the operator SecurityResult is sent.
func (p *VNCProxy) bridgeInit(operator, upstream net.Conn) ([]byte, error) {
	_ = operator.SetReadDeadline(time.Now().Add(p.dialTimeout))
	_ = upstream.SetDeadline(time.Now().Add(p.dialTimeout))
	defer func() {
		_ = operator.SetReadDeadline(time.Time{})
		_ = upstream.SetDeadline(time.Time{})
	}()

	var ci [1]byte
	if _, err := io.ReadFull(operator, ci[:]); err != nil {
		return nil, fmt.Errorf("read operator ClientInit: %w", err)
	}
	if _, err := upstream.Write(ci[:]); err != nil {
		return nil, fmt.Errorf("send upstream ClientInit: %w", err)
	}
	serverInit, err := readServerInit(upstream)
	if err != nil {
		return nil, err
	}
	if _, err := operator.Write(serverInit); err != nil {
		return nil, fmt.Errorf("relay ServerInit: %w", err)
	}
	return serverInit, nil
}

// dialUpstream connects to the upstream VNC server and authenticates as the
// gateway using VNC Authentication with the vault password, then performs the
// ClientInit/ServerInit exchange and returns the connection plus the raw
// ServerInit to relay to the operator.
func (p *VNCProxy) dialUpstream(ctx context.Context, leased *pam.LeasedSession) (net.Conn, error) {
	d := net.Dialer{Timeout: p.dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", leased.Target.Address)
	if err != nil {
		return nil, fmt.Errorf("dial vnc: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(p.dialTimeout))

	// ProtocolVersion exchange.
	var srvVer [12]byte
	if _, err := io.ReadFull(conn, srvVer[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read upstream version: %w", err)
	}
	if _, err := conn.Write([]byte(rfbProtocolVersion)); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Security types: server sends count, then that many type bytes.
	var nTypes [1]byte
	if _, err := io.ReadFull(conn, nTypes[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read upstream security count: %w", err)
	}
	if nTypes[0] == 0 {
		_ = conn.Close()
		return nil, errors.New("upstream rejected connection (no security types)")
	}
	types := make([]byte, nTypes[0])
	if _, err := io.ReadFull(conn, types); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read upstream security types: %w", err)
	}
	if !containsByte(types, rfbSecVNCAuth) {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream does not offer VNC Authentication (offered %v)", types)
	}
	if _, err := conn.Write([]byte{rfbSecVNCAuth}); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// VNC Auth: 16-byte challenge → DES(response) → SecurityResult.
	var challenge [16]byte
	if _, err := io.ReadFull(conn, challenge[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read challenge: %w", err)
	}
	response, err := vncEncryptChallenge(challenge[:], leased.Secret.Password)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err := conn.Write(response); err != nil {
		_ = conn.Close()
		return nil, err
	}
	var secResult [4]byte
	if _, err := io.ReadFull(conn, secResult[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read upstream security result: %w", err)
	}
	if binary.BigEndian.Uint32(secResult[:]) != 0 {
		_ = conn.Close()
		return nil, errors.New("upstream rejected vault credential")
	}
	// Leave the upstream positioned just before ClientInit; bridgeInit performs
	// the ClientInit/ServerInit exchange once the operator's shared flag arrives.
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// splice relays the RFB stream. Operator→upstream is parsed message-by-message
// so clipboard pastes can be gated; upstream→operator is copied through with
// frame-buffer recording.
func (p *VNCProxy) splice(ctx context.Context, operator, upstream net.Conn, session *models.PAMSession, rec *IORecorder, cancel context.CancelFunc) {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		p.forwardOperatorMessages(ctx, operator, upstream, session, rec)
	}()

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

// forwardOperatorMessages parses RFB client messages and forwards them to the
// upstream, gating ClientCutText (clipboard paste) against policy. A denied
// paste is dropped (not forwarded) and annotated; the session continues, since
// RFB client messages are self-delimiting and dropping one does not desync the
// stream.
func (p *VNCProxy) forwardOperatorMessages(ctx context.Context, operator, upstream net.Conn, session *models.PAMSession, rec *IORecorder) {
	for {
		// Honour the live soft-pause gate before reading the next operator
		// message: while an admin has frozen the session no further RFB
		// client message (pointer/key/cut-text) is pulled or forwarded to the
		// upstream server.
		rec.WaitWhilePaused()
		msg, msgType, err := readRFBClientMessage(operator)
		if err != nil {
			return
		}
		if msgType == rfbCMsgClientCutText {
			n := len(msg) - 8
			if n < 0 {
				n = 0
			}
			cmd := fmt.Sprintf("clipboard:paste %d bytes", n)
			rec.Record(DirInput, []byte(cmd+"\n"))
			decision, derr := p.sessions.LogCommand(ctx, session, cmd)
			if derr != nil || !decision.Allowed() {
				reason := decision.Reason
				if reason == "" {
					reason = "denied by command policy"
				}
				rec.Annotate(fmt.Sprintf("[clipboard paste denied: %s]", reason))
				continue
			}
		} else {
			rec.Record(DirInput, msg)
		}
		if _, err := upstream.Write(msg); err != nil {
			return
		}
	}
}

// --- RFB wire helpers -----------------------------------------------------

// readServerInit reads a ServerInit message: 2 width, 2 height, 16 pixel
// format, 4 name-length, then name-length bytes.
func readServerInit(r io.Reader) ([]byte, error) {
	head := make([]byte, 24)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, fmt.Errorf("read ServerInit head: %w", err)
	}
	nameLen := binary.BigEndian.Uint32(head[20:24])
	if nameLen > 64*1024 {
		return nil, fmt.Errorf("implausible ServerInit name length %d", nameLen)
	}
	name := make([]byte, nameLen)
	if _, err := io.ReadFull(r, name); err != nil {
		return nil, fmt.Errorf("read ServerInit name: %w", err)
	}
	return append(head, name...), nil
}

// readRFBClientMessage reads one RFB client→server message in full, returning
// the raw bytes (including the type byte) and the message type. Variable-length
// messages (SetEncodings, ClientCutText) are read to completion so the stream
// stays framed.
func readRFBClientMessage(r io.Reader) ([]byte, uint8, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return nil, 0, err
	}
	switch t[0] {
	case rfbCMsgSetPixelFormat:
		return readRFBFixed(r, t[0], 20)
	case rfbCMsgFramebufferUpdateRequest:
		return readRFBFixed(r, t[0], 10)
	case rfbCMsgKeyEvent:
		return readRFBFixed(r, t[0], 8)
	case rfbCMsgPointerEvent:
		return readRFBFixed(r, t[0], 6)
	case rfbCMsgSetEncodings:
		// 1 type + 1 pad + 2 count + 4*count.
		rest := make([]byte, 3)
		if _, err := io.ReadFull(r, rest); err != nil {
			return nil, t[0], err
		}
		count := binary.BigEndian.Uint16(rest[1:3])
		body := make([]byte, int(count)*4)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, t[0], err
		}
		return concat(t[0], rest, body), t[0], nil
	case rfbCMsgClientCutText:
		// 1 type + 3 pad + 4 length + body. RFC 6143 ClientCutText carries a
		// CARD32 length. TigerVNC's Extended Clipboard reuses this type with the
		// length's high bit set: interpreted as int32 the value is negative and
		// its magnitude is the body size (a 4-byte flags word followed by the
		// payload). Both forms are clipboard and gated identically.
		rest := make([]byte, 7)
		if _, err := io.ReadFull(r, rest); err != nil {
			return nil, t[0], err
		}
		raw := binary.BigEndian.Uint32(rest[3:7])
		var bodyLen int64
		if int32(raw) < 0 {
			bodyLen = int64(-int32(raw)) // extended clipboard: |length| is the body size
		} else {
			bodyLen = int64(raw)
		}
		if bodyLen > maxRFBCutTextLen {
			return nil, t[0], fmt.Errorf("ClientCutText too large (%d bytes)", bodyLen)
		}
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, t[0], err
		}
		return concat(t[0], rest, body), t[0], nil
	case rfbCMsgEnableContinuousUpdates:
		// 1 type + 1 enable + 2 x + 2 y + 2 width + 2 height = 10 bytes.
		return readRFBFixed(r, t[0], 10)
	case rfbCMsgXvp:
		// 1 type + 1 pad + 1 version + 1 code = 4 bytes.
		return readRFBFixed(r, t[0], 4)
	case rfbCMsgClientFence:
		// 1 type + 3 pad + 4 flags + 1 length + length bytes (length is a single
		// byte, max 64 per the fence spec but bounded at the wire maximum here).
		rest := make([]byte, 8)
		if _, err := io.ReadFull(r, rest); err != nil {
			return nil, t[0], err
		}
		length := int(rest[7])
		if length > maxRFBFenceLen {
			return nil, t[0], fmt.Errorf("ClientFence payload too large (%d bytes)", length)
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, t[0], err
		}
		return concat(t[0], rest, body), t[0], nil
	case rfbCMsgSetDesktopSize:
		// 1 type + 1 pad + 2 width + 2 height + 1 number-of-screens + 1 pad,
		// then number-of-screens × 16-byte screen records.
		rest := make([]byte, 7)
		if _, err := io.ReadFull(r, rest); err != nil {
			return nil, t[0], err
		}
		screens := int(rest[5])
		if screens > maxRFBScreens {
			return nil, t[0], fmt.Errorf("SetDesktopSize screen count too large (%d)", screens)
		}
		body := make([]byte, screens*16)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, t[0], err
		}
		return concat(t[0], rest, body), t[0], nil
	case rfbCMsgQEMU:
		return readRFBQEMUMessage(r, t[0])
	default:
		// Fail closed. The proxy must frame every client message to locate and
		// gate ClientCutText (clipboard). A message type whose framing the proxy
		// does not know has an unknown length, so we cannot find where the next
		// message begins. The only alternative — stop parsing and stream the
		// rest raw — would let clipboard data bypass policy, defeating the
		// gateway's purpose, so we terminate rather than fail open. The common
		// real-world extensions are framed in the cases above; supporting a
		// further extension means teaching this switch that message's framing,
		// never relaxing this default.
		return nil, t[0], fmt.Errorf("unsupported RFB client message type %d (gateway fails closed on unframable messages)", t[0])
	}
}

// readRFBQEMUMessage frames a QEMU Client Message (type 255). The first trailing
// byte is the sub-message type: ExtendedKeyEvent is a fixed 12-byte message;
// Audio is 2 bytes of operation followed, only for the set-format operation, by
// a 4-byte format trailer. Any other sub-message is unframable, so the proxy
// fails closed for it rather than guessing a length.
func readRFBQEMUMessage(r io.Reader, msgType uint8) ([]byte, uint8, error) {
	var sub [1]byte
	if _, err := io.ReadFull(r, sub[:]); err != nil {
		return nil, msgType, err
	}
	switch sub[0] {
	case qemuSubExtendedKeyEvent:
		// type + sub + 2 down-flag + 4 keysym + 4 keycode = 12 bytes; 2 already read.
		rest := make([]byte, 10)
		if _, err := io.ReadFull(r, rest); err != nil {
			return nil, msgType, err
		}
		return concat(msgType, sub[:], rest), msgType, nil
	case qemuSubAudio:
		op := make([]byte, 2)
		if _, err := io.ReadFull(r, op); err != nil {
			return nil, msgType, err
		}
		var trailer []byte
		if binary.BigEndian.Uint16(op) == qemuAudioSetFormat {
			// set-format trailer: sample-format(1) + channels(1) + frequency(4).
			trailer = make([]byte, 6)
			if _, err := io.ReadFull(r, trailer); err != nil {
				return nil, msgType, err
			}
		}
		out := concat(msgType, sub[:], op)
		out = append(out, trailer...)
		return out, msgType, nil
	default:
		return nil, msgType, fmt.Errorf("unsupported QEMU sub-message type %d (gateway fails closed on unframable messages)", sub[0])
	}
}

func readRFBFixed(r io.Reader, msgType uint8, restLen int) ([]byte, uint8, error) {
	rest := make([]byte, restLen-1)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, msgType, err
	}
	return concat(msgType, rest, nil), msgType, nil
}

func concat(first byte, a, b []byte) []byte {
	out := make([]byte, 0, 1+len(a)+len(b))
	out = append(out, first)
	out = append(out, a...)
	out = append(out, b...)
	return out
}

// writeVNCSecurityResult writes an RFB SecurityResult. On failure (RFB 3.8) a
// reason string is appended so the operator's client can surface it.
func writeVNCSecurityResult(conn net.Conn, ok bool, reason string) error {
	var b []byte
	if ok {
		b = []byte{0x00, 0x00, 0x00, 0x00}
	} else {
		b = []byte{0x00, 0x00, 0x00, 0x01}
		r := []byte(reason)
		l := make([]byte, 4)
		binary.BigEndian.PutUint32(l, uint32(len(r)))
		b = append(b, l...)
		b = append(b, r...)
	}
	_, err := conn.Write(b)
	return err
}

// vncEncryptChallenge encrypts a 16-byte VNC auth challenge with DES using the
// password as the key. VNC keys are the 8-byte password (NUL-padded /
// truncated) with each byte's bit order reversed, applied in ECB to both 8-byte
// halves of the challenge.
func vncEncryptChallenge(challenge []byte, password string) ([]byte, error) {
	if len(challenge) != 16 {
		return nil, fmt.Errorf("vnc challenge must be 16 bytes, got %d", len(challenge))
	}
	var key [8]byte
	for i := 0; i < 8 && i < len(password); i++ {
		key[i] = reverseBits(password[i])
	}
	// VNC's RFB "VNC Authentication" security type is defined by the protocol to
	// use single-DES; it is not a choice the gateway can strengthen without
	// breaking compatibility with every VNC server, so the weak-primitive warning
	// is expected and suppressed here.
	block, err := des.NewCipher(key[:]) //nolint:gosec // RFB VNC Authentication mandates DES
	if err != nil {
		return nil, fmt.Errorf("vnc des key: %w", err)
	}
	out := make([]byte, 16)
	block.Encrypt(out[0:8], challenge[0:8])
	block.Encrypt(out[8:16], challenge[8:16])
	return out, nil
}

// reverseBits reverses the bit order of a byte (VNC's DES key mangling).
func reverseBits(b byte) byte {
	var r byte
	for i := 0; i < 8; i++ {
		r = (r << 1) | (b & 1)
		b >>= 1
	}
	return r
}

func containsByte(s []byte, b byte) bool {
	for _, v := range s {
		if v == b {
			return true
		}
	}
	return false
}

// generateVNCChallenge returns a 16-byte random challenge (used by tests and by
// any future server-side auth path).
func generateVNCChallenge() ([]byte, error) {
	c := make([]byte, 16)
	if _, err := rand.Read(c); err != nil {
		return nil, err
	}
	return c, nil
}
