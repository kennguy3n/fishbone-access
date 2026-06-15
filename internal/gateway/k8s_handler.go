package gateway

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// K8sExecProxy is the gateway.ConnHandler for the Kubernetes-exec listener
// (:8443). It fronts `kubectl exec`/`attach`: the operator points kubectl at
// the gateway with the one-shot connect token as the bearer token. The proxy
// terminates TLS, redeems the token, dials the upstream kube-apiserver with the
// JIT-injected service-account credential, replays the (rewritten) HTTP request
// upstream, and splices the upgraded SPDY/WebSocket stream while recording both
// directions for replay.
type K8sExecProxy struct {
	broker      *pam.Broker
	sessions    *pam.SessionManager
	hub         *SessionHub
	store       ReplayStore
	tlsConfig   *tls.Config
	dialTimeout time.Duration
	dialer      TargetDialer
	recMaxBytes int
}

// K8sExecProxyConfig configures a K8sExecProxy.
type K8sExecProxyConfig struct {
	Broker      *pam.Broker
	Sessions    *pam.SessionManager
	Hub         *SessionHub
	Store       ReplayStore
	TLSConfig   *tls.Config
	DialTimeout time.Duration
	// Dialer establishes the upstream transport. Nil dials directly (the
	// default); a broker dialer routes via-agent targets through the tunnel.
	Dialer      TargetDialer
	RecMaxBytes int
}

// NewK8sExecProxy builds a K8sExecProxy. When no TLS config is supplied an
// ephemeral self-signed certificate is generated so the listener still serves
// HTTPS (operators must trust it out-of-band, e.g. --insecure-skip-tls-verify
// in dev); production wiring should pass a real keypair.
func NewK8sExecProxy(cfg K8sExecProxyConfig) (*K8sExecProxy, error) {
	if cfg.Broker == nil || cfg.Sessions == nil {
		return nil, errors.New("gateway: K8sExecProxy requires broker and session manager")
	}
	tlsCfg := cfg.TLSConfig
	if tlsCfg == nil {
		cert, err := ephemeralTLSCert()
		if err != nil {
			return nil, fmt.Errorf("gateway: k8s ephemeral cert: %w", err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	dt := cfg.DialTimeout
	if dt <= 0 {
		dt = 15 * time.Second
	}
	return &K8sExecProxy{
		broker:      cfg.Broker,
		sessions:    cfg.Sessions,
		hub:         cfg.Hub,
		store:       cfg.Store,
		tlsConfig:   tlsCfg,
		dialTimeout: dt,
		dialer:      resolveDialer(cfg.Dialer, dt),
		recMaxBytes: cfg.RecMaxBytes,
	}, nil
}

// Handle implements gateway.ConnHandler.
func (p *K8sExecProxy) Handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().String()

	tlsConn := tls.Server(conn, p.tlsConfig)
	hsCtx, hsCancel := context.WithTimeout(ctx, p.dialTimeout)
	defer hsCancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		logger.Warnf(ctx, "k8s-proxy: tls handshake from %s: %v", clientAddr, err)
		return
	}

	br := bufio.NewReader(tlsConn)
	req, err := http.ReadRequest(br)
	if err != nil {
		logger.Warnf(ctx, "k8s-proxy: read request from %s: %v", clientAddr, err)
		return
	}

	token := bearerToken(req.Header.Get("Authorization"))
	if token == "" {
		writeHTTPError(tlsConn, http.StatusUnauthorized, "missing bearer connect token")
		return
	}
	leased, err := p.broker.RedeemConnectToken(ctx, token, clientAddr)
	if err != nil {
		writeHTTPError(tlsConn, http.StatusUnauthorized, "connect token rejected")
		logger.Warnf(ctx, "k8s-proxy: redeem from %s failed: %v", clientAddr, err)
		return
	}
	if leased.Target.Protocol != models.PAMProtocolK8sExec {
		writeHTTPError(tlsConn, http.StatusBadRequest, "token is not for a kubernetes target")
		// RedeemConnectToken already consumed the token and opened the session;
		// reconcile it closed so it does not orphan active with no proxy.
		reconcileOrphanSession(ctx, p.sessions, leased.Session, "k8s-proxy")
		return
	}
	session := leased.Session
	logger.Infof(ctx, "k8s-proxy: session %s opened for %s → %s %s", session.ID, session.Subject, req.Method, req.URL.Path)

	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	rec := NewIORecorder(sessCtx, session.ID.String(), p.recMaxBytes)
	rec.Annotate(fmt.Sprintf("[exec %s %s]", req.Method, req.URL.RequestURI()))
	if p.hub != nil {
		defer p.hub.Register(session.ID, session.WorkspaceID, session.Subject, rec, cancel)()
	}
	defer func() {
		flushCtx, fcancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer fcancel()
		if err := rec.Flush(flushCtx, p.store); err != nil {
			logger.Warnf(ctx, "k8s-proxy: flush replay %s: %v", session.ID, err)
		}
		if recording := rec.Recording(); recording.Stored {
			if err := p.sessions.RecordRecording(flushCtx, session, pam.RecordingRef{
				Key: recording.Key, SHA256: recording.SHA256, Bytes: recording.Bytes, Truncated: recording.Truncated,
			}); err != nil {
				logger.Warnf(ctx, "k8s-proxy: record recording evidence %s: %v", session.ID, err)
			}
		}
		if err := p.sessions.CloseSession(flushCtx, session.WorkspaceID, session.ID); err != nil {
			logger.Warnf(ctx, "k8s-proxy: close session %s: %v", session.ID, err)
		}
	}()

	// Log the exec request itself as the session "command" so it is gated and
	// audited like any other privileged action.
	if decision, derr := p.sessions.LogCommand(sessCtx, session, req.Method+" "+req.URL.RequestURI()); derr != nil || !decision.Allowed() {
		writeHTTPError(tlsConn, http.StatusForbidden, "pam-gateway: exec denied by command policy")
		return
	}

	upstream, err := p.dialUpstream(sessCtx, leased)
	if err != nil {
		writeHTTPError(tlsConn, http.StatusBadGateway, "upstream apiserver connection failed")
		rec.Annotate(fmt.Sprintf("[upstream connect failed: %v]", err))
		logger.Warnf(ctx, "k8s-proxy: upstream %s: %v", leased.Target.Address, err)
		return
	}
	defer upstream.Close()

	p.rewriteForUpstream(req, leased)
	if err := req.Write(upstream); err != nil {
		logger.Warnf(ctx, "k8s-proxy: write upstream request: %v", err)
		return
	}
	// Flush any bytes the operator already pipelined after the request head.
	if n := br.Buffered(); n > 0 {
		buffered, _ := br.Peek(n)
		if _, err := upstream.Write(buffered); err != nil {
			return
		}
		rec.Record(DirInput, buffered)
		_, _ = br.Discard(n)
	}

	p.splice(sessCtx, tlsConn, br, upstream, rec, cancel)
}

// dialUpstream opens a TLS connection to the upstream apiserver. When the
// target config carries no CA bundle the connection skips verification (the
// gateway is the trust boundary); a configured "ca_cert" (PEM) pins the
// apiserver identity.
func (p *K8sExecProxy) dialUpstream(ctx context.Context, leased *pam.LeasedSession) (net.Conn, error) {
	host, _, err := net.SplitHostPort(leased.Target.Address)
	if err != nil {
		host = leased.Target.Address
	}
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if ca := decodeTargetConfig(leased.Target.Config)["ca_cert"]; ca != "" {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM([]byte(ca)) {
			cfg.RootCAs = pool
		}
	} else {
		cfg.InsecureSkipVerify = true //nolint:gosec // no CA pinned: the gateway is the audited trust boundary to the apiserver.
	}
	// Obtain the raw transport through the dialer seam (direct or brokered via an
	// agent tunnel), then layer TLS on top so a via-agent apiserver is reached
	// over the tunnel exactly as a direct dial would be.
	raw, err := p.dialer.DialTarget(ctx, leased.Target)
	if err != nil {
		return nil, fmt.Errorf("dial apiserver: %w", err)
	}
	tlsConn := tls.Client(raw, cfg)
	hsCtx, cancel := context.WithTimeout(ctx, p.dialTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("tls apiserver: %w", err)
	}
	return tlsConn, nil
}

// rewriteForUpstream injects the upstream credential and fixes routing headers
// so the request authenticates as the gateway's service account, not the
// operator's connect token.
func (p *K8sExecProxy) rewriteForUpstream(req *http.Request, leased *pam.LeasedSession) {
	host := leased.Target.Address
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	req.Host = host
	req.URL.Host = leased.Target.Address
	req.URL.Scheme = "https"
	req.RequestURI = ""

	switch {
	case leased.Secret.Token != "":
		req.Header.Set("Authorization", "Bearer "+leased.Secret.Token)
	case leased.Secret.Username != "":
		req.Header.Set("Authorization", "Basic "+basicAuth(leased.Secret.Username, leased.Secret.Password))
	default:
		req.Header.Del("Authorization")
	}
}

// splice copies bytes in both directions, recording the streamed session.
func (p *K8sExecProxy) splice(ctx context.Context, operator net.Conn, operatorBuf *bufio.Reader, upstream net.Conn, rec *IORecorder, cancel context.CancelFunc) {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		_, _ = io.Copy(upstream, rec.TeeReader(DirInput, operatorBuf))
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

// --- helpers ---

// bearerToken extracts the token from an "Authorization: Bearer <t>" header.
func bearerToken(header string) string {
	const prefix = "Bearer "
	if len(header) > len(prefix) && strings.EqualFold(header[:len(prefix)], prefix) {
		return strings.TrimSpace(header[len(prefix):])
	}
	return ""
}

// basicAuth encodes credentials for an HTTP Basic Authorization header.
func basicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

// writeHTTPError writes a minimal HTTP error response to the operator.
func writeHTTPError(w io.Writer, status int, msg string) {
	body := msg + "\n"
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
}

// ephemeralTLSCert mints a short-lived self-signed P-256 certificate for the
// operator-facing listener when no keypair is configured.
func ephemeralTLSCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "shieldnet-pam-gateway"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "shieldnet-pam-gateway"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
