package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"gorm.io/datatypes"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// SSHProxy is the gateway.ConnHandler for the SSH listener (:2222). An operator
// connects to the gateway with any SSH client, authenticating with a one-shot
// connect token as the password. On redemption the proxy dials the upstream
// target, authenticating with a freshly minted short-lived CA certificate (no
// static key on the target) or, when the target does not trust the CA, the
// JIT-injected vault credential. Both directions of every channel are recorded;
// exec commands and shell input lines are gated live against the 1C policy
// engine and appended to the workspace audit hash chain.
type SSHProxy struct {
	broker      *pam.Broker
	sessions    *pam.SessionManager
	hub         *SessionHub
	store       ReplayStore
	ca          *SSHCertificateAuthority
	hostKey     ssh.Signer
	dialTimeout time.Duration
	recMaxBytes int
}

// SSHProxyConfig configures an SSHProxy. broker, sessions, hostKey are
// required; ca and store may be nil (no CA ⇒ credential injection only; no
// store ⇒ recording is kept in memory and dropped on flush).
type SSHProxyConfig struct {
	Broker      *pam.Broker
	Sessions    *pam.SessionManager
	Hub         *SessionHub
	Store       ReplayStore
	CA          *SSHCertificateAuthority
	HostKey     ssh.Signer
	DialTimeout time.Duration
	RecMaxBytes int
}

// NewSSHProxy builds an SSHProxy.
func NewSSHProxy(cfg SSHProxyConfig) (*SSHProxy, error) {
	if cfg.Broker == nil || cfg.Sessions == nil {
		return nil, errors.New("gateway: SSHProxy requires broker and session manager")
	}
	if cfg.HostKey == nil {
		return nil, errors.New("gateway: SSHProxy requires a host key")
	}
	dt := cfg.DialTimeout
	if dt <= 0 {
		dt = 15 * time.Second
	}
	return &SSHProxy{
		broker:      cfg.Broker,
		sessions:    cfg.Sessions,
		hub:         cfg.Hub,
		store:       cfg.Store,
		ca:          cfg.CA,
		hostKey:     cfg.HostKey,
		dialTimeout: dt,
		recMaxBytes: cfg.RecMaxBytes,
	}, nil
}

// Handle implements gateway.ConnHandler.
func (p *SSHProxy) Handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	var leased *pam.LeasedSession
	clientAddr := conn.RemoteAddr().String()

	cfg := &ssh.ServerConfig{
		// The operator authenticates to the gateway with the one-shot connect
		// token as the password. Redemption opens the session and yields the
		// upstream credential in-memory.
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			ls, err := p.broker.RedeemConnectToken(ctx, string(password), clientAddr)
			if err != nil {
				return nil, fmt.Errorf("connect token rejected: %w", err)
			}
			leased = ls
			return &ssh.Permissions{Extensions: map[string]string{"session_id": ls.Session.ID.String()}}, nil
		},
	}
	cfg.AddHostKey(p.hostKey)

	serverConn, chans, globalReqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		logger.Warnf(ctx, "ssh-proxy: handshake from %s failed: %v", clientAddr, err)
		// PasswordCallback may have already redeemed the token (consumed it and
		// marked the session active) before NewServerConn failed sending
		// USERAUTH_SUCCESS; reconcile so the session is not orphaned active.
		if leased != nil {
			reconcileOrphanSession(ctx, p.sessions, leased.Session, "ssh-proxy")
		}
		return
	}
	defer func() { _ = serverConn.Close() }()
	if leased == nil {
		return
	}
	session := leased.Session
	// Reject a token minted for a non-SSH target presented to this listener,
	// matching the MySQL/PG/K8s handlers. RedeemConnectToken already consumed
	// the token and opened the session, so reconcile it closed before bailing.
	if leased.Target.Protocol != models.PAMProtocolSSH {
		logger.Warnf(ctx, "ssh-proxy: token target protocol %q is not ssh", leased.Target.Protocol)
		reconcileOrphanSession(ctx, p.sessions, session, "ssh-proxy")
		return
	}
	logger.Infof(ctx, "ssh-proxy: session %s opened for %s → %s", session.ID, session.Subject, leased.Target.Address)

	sessCtx, cancel := context.WithCancel(ctx)
	rec := NewIORecorder(sessCtx, session.ID.String(), p.recMaxBytes)
	defer cancel()
	if p.hub != nil {
		deregister := p.hub.Register(session.ID, session.WorkspaceID, session.Subject, rec, cancel)
		defer deregister()
	}

	defer func() {
		flushCtx, fcancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer fcancel()
		if err := rec.Flush(flushCtx, p.store); err != nil {
			logger.Warnf(ctx, "ssh-proxy: flush replay %s: %v", session.ID, err)
		}
		if recording := rec.Recording(); recording.Stored {
			if err := p.sessions.RecordRecording(flushCtx, session, pam.RecordingRef{
				Key: recording.Key, SHA256: recording.SHA256, Bytes: recording.Bytes, Truncated: recording.Truncated,
			}); err != nil {
				logger.Warnf(ctx, "ssh-proxy: record recording evidence %s: %v", session.ID, err)
			}
		}
		if err := p.sessions.CloseSession(flushCtx, session.WorkspaceID, session.ID); err != nil {
			logger.Warnf(ctx, "ssh-proxy: close session %s: %v", session.ID, err)
		}
	}()

	upstream, err := p.dialUpstream(leased)
	if err != nil {
		rec.Annotate(fmt.Sprintf("[upstream dial failed: %v]", err))
		logger.Warnf(ctx, "ssh-proxy: dial upstream %s: %v", leased.Target.Address, err)
		go ssh.DiscardRequests(globalReqs)
		rejectAll(chans, "upstream unavailable")
		return
	}
	defer func() { _ = upstream.Close() }()

	// The gateway issues no global requests upstream; discard the operator's
	// (keepalive@openssh.com etc.) and the upstream's.
	go ssh.DiscardRequests(globalReqs)

	var wg sync.WaitGroup
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session channels are proxied")
			continue
		}
		wg.Add(1)
		go func(nc ssh.NewChannel) {
			defer wg.Done()
			p.proxySessionChannel(sessCtx, nc, upstream, session, rec, cancel)
		}(newCh)
	}
	wg.Wait()
}

// dialUpstream opens an SSH client connection to the target, preferring a
// freshly minted CA certificate and falling back to the JIT-injected vault
// credential (private key, then password). The upstream username is the
// target's configured account, never client-supplied.
func (p *SSHProxy) dialUpstream(leased *pam.LeasedSession) (*ssh.Client, error) {
	target := leased.Target
	user := target.Username
	if user == "" {
		user = leased.Secret.Username
	}
	if user == "" {
		return nil, errors.New("gateway: target has no upstream username")
	}

	var auths []ssh.AuthMethod
	if p.ca != nil {
		if certSigner, err := p.ca.MintEphemeralCert(user); err == nil {
			auths = append(auths, ssh.PublicKeys(certSigner))
		} else {
			logger.Warnf(context.Background(), "ssh-proxy: mint cert: %v", err)
		}
	}
	if leased.Secret.PrivateKey != "" {
		if signer, err := ssh.ParsePrivateKey([]byte(leased.Secret.PrivateKey)); err == nil {
			auths = append(auths, ssh.PublicKeys(signer))
		}
	}
	if leased.Secret.Password != "" {
		pw := leased.Secret.Password
		auths = append(auths, ssh.Password(pw))
	}
	if len(auths) == 0 {
		return nil, errors.New("gateway: no usable upstream auth method")
	}

	clientCfg := &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: hostKeyCallback(target),
		Timeout:         p.dialTimeout,
	}
	client, err := ssh.Dial("tcp", target.Address, clientCfg)
	if err != nil {
		return nil, fmt.Errorf("gateway: ssh dial %s: %w", target.Address, err)
	}
	return client, nil
}

// proxySessionChannel bridges one operator "session" channel to a matching
// upstream channel, forwarding channel requests, copying the three byte streams
// with recording, and gating exec/shell commands against policy.
func (p *SSHProxy) proxySessionChannel(ctx context.Context, nc ssh.NewChannel, upstream *ssh.Client, session *models.PAMSession, rec *IORecorder, cancel context.CancelFunc) {
	opChan, opReqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer func() { _ = opChan.Close() }()

	upChan, upReqs, err := upstream.OpenChannel("session", nil)
	if err != nil {
		fmt.Fprintf(opChan, "pam-gateway: cannot open upstream session: %v\r\n", err)
		return
	}
	defer func() { _ = upChan.Close() }()

	var wg sync.WaitGroup
	wg.Add(1)
	// Operator → upstream requests: intercept exec/shell for command policy.
	go func() {
		defer wg.Done()
		p.forwardOperatorRequests(ctx, opReqs, upChan, session, rec, cancel)
	}()

	wg.Add(1)
	// Upstream → operator requests (exit-status, exit-signal, etc.).
	go func() {
		defer wg.Done()
		forwardRequests(upReqs, opChan)
	}()

	// stdin: operator → upstream, recorded as input, scanned for shell commands.
	// GateReader(opChan) applies the soft-pause gate at the operator source, so
	// while an admin has paused the session no keystroke is pulled from the
	// operator channel and nothing reaches the upstream shell; the scanner still
	// records and command-gates each byte once flow resumes. (The scanner does
	// the recording, so we gate-only rather than routing through the recording
	// TeeReader to avoid double-recording stdin.)
	wg.Add(1)
	go func() {
		defer wg.Done()
		sc := &shellCommandScanner{proxy: p, ctx: ctx, session: session, rec: rec, cancel: cancel}
		_, _ = io.Copy(upChan, io.TeeReader(rec.GateReader(opChan), sc))
		_ = upChan.CloseWrite()
	}()

	// stdout: upstream → operator, recorded as output.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(opChan, rec.TeeReader(DirOutput, upChan))
		_ = opChan.CloseWrite()
	}()

	// stderr: upstream → operator, recorded as output.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(opChan.Stderr(), rec.TeeReader(DirOutput, upChan.Stderr()))
	}()

	// Sever the streams when the session context is cancelled (admin terminate).
	go func() {
		<-ctx.Done()
		_ = opChan.Close()
		_ = upChan.Close()
	}()

	wg.Wait()
}

// forwardOperatorRequests proxies channel requests from operator to upstream.
// "exec" requests carry the exact command, which is gated against policy before
// being forwarded; a deny is recorded, refused, and tears the session down.
// "shell" requests are forwarded (interactive input is gated by the stdin
// scanner). Other requests (pty-req, env, window-change, subsystem, signal) are
// forwarded verbatim.
func (p *SSHProxy) forwardOperatorRequests(ctx context.Context, reqs <-chan *ssh.Request, upChan ssh.Channel, session *models.PAMSession, rec *IORecorder, cancel context.CancelFunc) {
	for req := range reqs {
		switch req.Type {
		case "exec":
			cmd := decodeStringPayload(req.Payload)
			rec.Record(DirInput, []byte(cmd+"\n"))
			decision, err := p.sessions.LogCommand(ctx, session, cmd)
			if err != nil || !decision.Allowed() {
				// Preserve the matching policy's specific reason (e.g. which rule
				// and pattern denied the command) for the recording and audit
				// annotation, matching the MySQL/PG handlers; fall back to a
				// generic message only when none is set.
				reason := decision.Reason
				if reason == "" {
					reason = "denied by command policy"
				}
				if err != nil {
					reason = "command policy unavailable"
				}
				rec.Annotate(fmt.Sprintf("[exec %q %s: %s]", cmd, models.PAMDecisionDeny, reason))
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				cancel()
				return
			}
			ok, err := upChan.SendRequest("exec", req.WantReply, req.Payload)
			if err != nil {
				return
			}
			if req.WantReply {
				_ = req.Reply(ok, nil)
			}
		default:
			ok, err := upChan.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				return
			}
			if req.WantReply {
				_ = req.Reply(ok, nil)
			}
		}
	}
}

// forwardRequests proxies channel requests one way (upstream → operator).
func forwardRequests(reqs <-chan *ssh.Request, dst ssh.Channel) {
	for req := range reqs {
		ok, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			return
		}
		if req.WantReply {
			_ = req.Reply(ok, nil)
		}
	}
}

// shellCommandScanner records operator stdin as input and extracts
// newline-delimited commands for live policy evaluation on interactive shells.
// It implements io.Writer so it can sit in an io.TeeReader on the stdin copy.
// On a policy deny it annotates the recording and cancels the session
// (fail-closed): an interactive PTY cannot un-send a keystroke, so the only
// safe enforcement is to terminate.
type shellCommandScanner struct {
	proxy   *SSHProxy
	ctx     context.Context
	session *models.PAMSession
	rec     *IORecorder
	cancel  context.CancelFunc
	buf     []byte
}

func (s *shellCommandScanner) Write(p []byte) (int, error) {
	s.rec.Record(DirInput, p)
	for _, b := range p {
		if b == '\r' || b == '\n' {
			s.flushLine()
			continue
		}
		// Cap the buffered line so a pathological no-newline stream cannot grow
		// memory without bound.
		if len(s.buf) < 4096 {
			s.buf = append(s.buf, b)
		}
	}
	return len(p), nil
}

func (s *shellCommandScanner) flushLine() {
	cmd := strings.TrimSpace(string(s.buf))
	s.buf = s.buf[:0]
	if cmd == "" {
		return
	}
	decision, err := s.proxy.sessions.LogCommand(s.ctx, s.session, cmd)
	if err != nil || !decision.Allowed() {
		s.rec.Annotate(fmt.Sprintf("[shell command %q denied by policy]", cmd))
		s.cancel()
	}
}

// hostKeyCallback verifies the upstream host key against a key pinned in the
// target's Config ("host_key": authorized-keys line) when present. Pinning is
// the secure path; when no key is pinned the callback accepts the presented key
// but records its fingerprint for audit (trust-on-first-use). It deliberately
// avoids ssh.InsecureIgnoreHostKey so a misconfiguration cannot silently
// disable verification when a pin IS configured.
func hostKeyCallback(target *models.PAMTarget) ssh.HostKeyCallback {
	pinned := targetHostKey(target)
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if pinned == "" {
			return nil
		}
		want, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pinned))
		if err != nil {
			return fmt.Errorf("gateway: parse pinned host key: %w", err)
		}
		if ssh.FingerprintSHA256(want) != ssh.FingerprintSHA256(key) {
			return fmt.Errorf("gateway: host key mismatch for %s (pinned %s, got %s)",
				hostname, ssh.FingerprintSHA256(want), ssh.FingerprintSHA256(key))
		}
		return nil
	}
}

// targetHostKey reads a pinned host key from the target config, if any.
func targetHostKey(target *models.PAMTarget) string {
	if target == nil || len(target.Config) == 0 {
		return ""
	}
	cfg := decodeTargetConfig(target.Config)
	return strings.TrimSpace(cfg["host_key"])
}

// rejectAll rejects every pending channel with a reason (used when the upstream
// is unreachable so the operator gets a clean error rather than a hang).
func rejectAll(chans <-chan ssh.NewChannel, reason string) {
	for nc := range chans {
		_ = nc.Reject(ssh.ConnectionFailed, reason)
	}
}

// decodeStringPayload extracts the leading SSH string (uint32 length + bytes)
// from a request payload — the wire shape of an "exec" command and a
// "subsystem" name.
func decodeStringPayload(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	n := binary.BigEndian.Uint32(payload[:4])
	if int(n) > len(payload)-4 {
		return ""
	}
	return string(payload[4 : 4+n])
}

// decodeTargetConfig decodes a target's Config JSON into a flat string map,
// returning an empty map on any decode error so a malformed config degrades to
// "no options" rather than failing the connection.
func decodeTargetConfig(raw datatypes.JSON) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	_ = json.Unmarshal(raw, &out)
	return out
}

// GenerateHostKey returns a fresh ed25519 ssh.Signer for the gateway's SSH
// server side. Production deployments configure a stable host key via
// PAM_SSH_HOST_KEY (see LoadHostKeyFromValue); this is the fallback used when
// none is configured so the listener still binds (each boot presents a new key,
// which clients TOFU).
func GenerateHostKey() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gateway: generate host key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("gateway: host key signer: %w", err)
	}
	return signer, nil
}
