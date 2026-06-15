package broker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// This file is the AGENT side of the tunnel (used by cmd/access-target-agent).
// It lives in the broker package so it shares the wire protocol with the relay
// — there is exactly one definition of the control/dial frames, so the two ends
// cannot drift. The agent dials OUT to the relay, multiplexes with yamux as the
// client, advertises what it can reach, heartbeats, and services the relay's
// dial streams by connecting to the requested upstream on its private network.

// GenerateAgentKey creates a fresh ECDSA P-256 key and a PEM CSR for it. The
// CSR subject is irrelevant (the control plane assigns identity), so it is left
// minimal. The private key never leaves the agent host.
func GenerateAgentKey() (key *ecdsa.PrivateKey, csrPEM []byte, keyPEM []byte, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "access-target-agent"},
	}, key)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	return key, pemBlock("CERTIFICATE REQUEST", csrDER), pemBlock("PRIVATE KEY", keyDER), nil
}

// AgentDialFunc connects to an upstream target on the agent's side of the
// tunnel. It is injectable so tests can substitute an in-memory upstream.
type AgentDialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// AgentConfig configures the outbound agent client.
type AgentConfig struct {
	// RelayAddr is the control-plane relay address to dial (host:port).
	RelayAddr string
	// ServerName is the TLS server name to verify the relay certificate
	// against. Defaults to the host part of RelayAddr.
	ServerName string
	// ClientCert is the issued agent client certificate + key.
	ClientCert tls.Certificate
	// RootCAs verifies the relay's server certificate (the agent CA pool).
	RootCAs *x509.CertPool
	// Reachable is the set of destinations this agent advertises it can reach.
	Reachable    []ReachableSpec
	AgentVersion string
	Platform     string
	// HeartbeatInterval defaults to 20s.
	HeartbeatInterval time.Duration
	// UpstreamDialTimeout bounds dialing an upstream target. Defaults to 10s.
	UpstreamDialTimeout time.Duration
	// Dial dials upstream targets. Defaults to a net.Dialer.
	Dial AgentDialFunc
}

// Agent is the outbound connector client.
type Agent struct {
	cfg AgentConfig
}

// NewAgent builds an agent with defaults applied.
func NewAgent(cfg AgentConfig) *Agent {
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 20 * time.Second
	}
	if cfg.UpstreamDialTimeout <= 0 {
		cfg.UpstreamDialTimeout = 10 * time.Second
	}
	if cfg.ServerName == "" {
		if host, _, err := net.SplitHostPort(cfg.RelayAddr); err == nil {
			cfg.ServerName = host
		} else {
			cfg.ServerName = cfg.RelayAddr
		}
	}
	if cfg.Dial == nil {
		d := &net.Dialer{Timeout: cfg.UpstreamDialTimeout}
		cfg.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			return d.DialContext(ctx, network, address)
		}
	}
	return &Agent{cfg: cfg}
}

// Run dials the relay, brings up the tunnel, registers, heartbeats, and serves
// dial streams until ctx is cancelled or the connection drops. It returns the
// terminating error so the caller (cmd) can back off and reconnect.
func (a *Agent) Run(ctx context.Context) error {
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{a.cfg.ClientCert},
		RootCAs:      a.cfg.RootCAs,
		ServerName:   a.cfg.ServerName,
		MinVersion:   tls.VersionTLS12,
	}
	dialer := &tls.Dialer{Config: tlsCfg}
	conn, err := dialer.DialContext(ctx, "tcp", a.cfg.RelayAddr)
	if err != nil {
		return fmt.Errorf("broker: dial relay: %w", err)
	}
	return a.serve(ctx, conn)
}

// serve runs the agent over an established (mTLS) connection. Split out so an
// integration test can drive it over an in-memory pipe.
func (a *Agent) serve(ctx context.Context, conn net.Conn) error {
	ycfg := yamux.DefaultConfig()
	ycfg.Logger = noopLogger{}
	ycfg.LogOutput = nil
	ycfg.EnableKeepAlive = true
	ycfg.KeepAliveInterval = 30 * time.Second
	session, err := yamux.Client(conn, ycfg)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("broker: yamux client: %w", err)
	}
	defer func() { _ = session.Close() }()

	control, err := session.Open()
	if err != nil {
		return fmt.Errorf("broker: open control stream: %w", err)
	}

	var writeMu sync.Mutex
	send := func(msg ControlMessage) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return writeJSONLine(control, msg)
	}

	if err := send(ControlMessage{Type: ControlTypeRegister, Register: &RegisterPayload{
		AgentVersion: a.cfg.AgentVersion,
		Platform:     a.cfg.Platform,
		Reachable:    a.cfg.Reachable,
	}}); err != nil {
		return fmt.Errorf("broker: register: %w", err)
	}
	logger.Infof(ctx, "agent: registered with relay %s (%d reachable specs)", a.cfg.RelayAddr, len(a.cfg.Reachable))

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Heartbeat loop.
	go func() {
		t := time.NewTicker(a.cfg.HeartbeatInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := send(ControlMessage{Type: ControlTypeHeartbeat}); err != nil {
					logger.Warnf(ctx, "agent: heartbeat failed: %v", err)
					cancel()
					return
				}
			}
		}
	}()

	// Close the session when ctx is cancelled so Accept unblocks.
	go func() {
		<-ctx.Done()
		_ = session.Close()
	}()

	// Accept and service dial streams from the relay.
	for {
		stream, err := session.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("broker: accept dial stream: %w", err)
		}
		go a.handleDial(ctx, stream)
	}
}

// handleDial services one relay→agent dial stream: read the target, connect to
// it on the agent's side, acknowledge, then pipe bytes both ways.
func (a *Agent) handleDial(ctx context.Context, stream net.Conn) {
	defer stream.Close()

	_ = stream.SetReadDeadline(time.Now().Add(a.cfg.UpstreamDialTimeout + 5*time.Second))
	var req DialRequest
	if err := readJSONLine(stream, &req); err != nil {
		logger.Warnf(ctx, "agent: read dial request: %v", err)
		return
	}
	_ = stream.SetReadDeadline(time.Time{})

	dctx, cancel := context.WithTimeout(ctx, a.cfg.UpstreamDialTimeout)
	upstream, err := a.cfg.Dial(dctx, "tcp", req.Target)
	cancel()
	if err != nil {
		_ = writeJSONLine(stream, DialResponse{OK: false, Error: "agent could not reach target"})
		logger.Warnf(ctx, "agent: dial upstream %s: %v", req.Target, err)
		return
	}
	defer upstream.Close()

	if err := writeJSONLine(stream, DialResponse{OK: true}); err != nil {
		logger.Warnf(ctx, "agent: write dial response: %v", err)
		return
	}
	pipe(stream, upstream)
}

// pipe copies bytes bidirectionally between the tunnel stream and the upstream
// connection until either side closes, then tears both down.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		// Half-close the write side so the peer sees EOF while the reverse copy
		// keeps draining. A net.TCPConn/tls.Conn exposes CloseWrite() directly.
		// A yamux *Stream does not, but its Close() on an established stream is a
		// half-close too: it sends a FIN (state → localClose) and Read keeps
		// returning buffered/in-flight data until the peer FINs — so the fallback
		// does not truncate the other direction.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

// LoadClientCert builds a tls.Certificate from PEM cert + key bytes.
func LoadClientCert(certPEM, keyPEM []byte) (tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("broker: load client certificate: %w", err)
	}
	return cert, nil
}

// PoolFromPEM builds a cert pool from a PEM bundle.
func PoolFromPEM(caPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("broker: no certificates in CA PEM")
	}
	return pool, nil
}
