// Command access-target-agent is the outbound connector an SME runs on one host
// inside their private network. It dials OUT to the ShieldNet Access control
// plane over mTLS and brokers privileged sessions (SSH/DB/...) to private
// targets, so the customer never opens an inbound firewall port.
//
// Lifecycle:
//
//  1. First run: with a one-shot enrollment token (ACCESS_AGENT_TOKEN), it
//     generates an ECDSA key locally, sends a CSR to the control plane's public
//     enrollment endpoint, and persists the issued client certificate, the CA,
//     and the relay address under ACCESS_AGENT_STATE_DIR. The private key never
//     leaves the host.
//  2. Every run: it loads that identity, dials the relay, advertises the
//     destinations it can reach (ACCESS_AGENT_REACHABLE), heartbeats, and serves
//     the relay's dial streams by connecting to the requested upstream — with an
//     automatic reconnect/backoff loop until SIGINT/SIGTERM.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/broker"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// version is overridable at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		logger.Errorf(context.Background(), "access-target-agent: fatal: %v", err)
		os.Exit(1)
	}
}

type agentEnv struct {
	apiURL     string
	token      string
	stateDir   string
	reachable  []broker.ReachableSpec
	relayAddr  string // optional override
	serverName string // optional override
	apiCAFile  string // optional extra CA to trust the API endpoint
}

func loadEnv() agentEnv {
	return agentEnv{
		apiURL:     strings.TrimRight(os.Getenv("ACCESS_AGENT_API_URL"), "/"),
		token:      os.Getenv("ACCESS_AGENT_TOKEN"),
		stateDir:   envDefault("ACCESS_AGENT_STATE_DIR", "./agent-state"),
		reachable:  parseReachable(os.Getenv("ACCESS_AGENT_REACHABLE")),
		relayAddr:  os.Getenv("ACCESS_AGENT_RELAY_ADDR"),
		serverName: os.Getenv("ACCESS_AGENT_RELAY_SERVERNAME"),
		apiCAFile:  os.Getenv("ACCESS_AGENT_API_CA_FILE"),
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	env := loadEnv()
	logger.Infof(ctx, "access-target-agent: starting version=%s platform=%s state=%s", version, platform(), env.stateDir)

	identity, err := ensureIdentity(ctx, env)
	if err != nil {
		return err
	}

	clientCert, err := broker.LoadClientCert(identity.certPEM, identity.keyPEM)
	if err != nil {
		return err
	}
	pool, err := broker.PoolFromPEM(identity.caPEM)
	if err != nil {
		return err
	}
	relayAddr := identity.relayAddr
	if env.relayAddr != "" {
		relayAddr = env.relayAddr
	}
	if relayAddr == "" {
		return errors.New("access-target-agent: no relay address (enrollment did not return one and ACCESS_AGENT_RELAY_ADDR is unset)")
	}

	agent := broker.NewAgent(broker.AgentConfig{
		RelayAddr:    relayAddr,
		ServerName:   env.serverName,
		ClientCert:   clientCert,
		RootCAs:      pool,
		Reachable:    env.reachable,
		AgentVersion: version,
		Platform:     platform(),
	})

	logger.Infof(ctx, "access-target-agent: enrolled agent=%s relay=%s reachable=%d", identity.agentID, relayAddr, len(env.reachable))
	return runWithReconnect(ctx, agent, relayAddr)
}

// runWithReconnect runs the agent, reconnecting with capped exponential backoff
// whenever the tunnel drops, until ctx is cancelled.
func runWithReconnect(ctx context.Context, agent *broker.Agent, relayAddr string) error {
	const (
		baseBackoff = time.Second
		maxBackoff  = 30 * time.Second
	)
	backoff := baseBackoff
	for {
		start := time.Now()
		err := agent.Run(ctx)
		if ctx.Err() != nil {
			logger.Infof(ctx, "access-target-agent: shutting down")
			return nil
		}
		if err != nil {
			logger.Warnf(ctx, "access-target-agent: tunnel to %s ended: %v", relayAddr, err)
		}
		// A tunnel that stayed up a while resets the backoff.
		if time.Since(start) > maxBackoff {
			backoff = baseBackoff
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// identity is the persisted agent identity loaded from (or written to) the
// state directory.
type identity struct {
	agentID   string
	relayAddr string
	keyPEM    []byte
	certPEM   []byte
	caPEM     []byte
}

const (
	keyFile  = "agent.key"
	certFile = "agent.crt"
	caFile   = "relay-ca.crt"
	metaFile = "agent.json"
)

type meta struct {
	AgentID   string    `json:"agent_id"`
	RelayAddr string    `json:"relay_addr"`
	NotAfter  time.Time `json:"not_after"`
}

// ensureIdentity loads a previously enrolled identity, or enrolls now using the
// one-shot token when none is present.
func ensureIdentity(ctx context.Context, env agentEnv) (*identity, error) {
	if id, ok, err := loadIdentity(env.stateDir); err != nil {
		return nil, err
	} else if ok {
		logger.Infof(ctx, "access-target-agent: loaded existing identity from %s", env.stateDir)
		return id, nil
	}
	if env.token == "" {
		return nil, fmt.Errorf("access-target-agent: no saved identity in %s and ACCESS_AGENT_TOKEN is empty — provide an enrollment token", env.stateDir)
	}
	if env.apiURL == "" {
		return nil, errors.New("access-target-agent: ACCESS_AGENT_API_URL is required to enroll")
	}
	return enroll(ctx, env)
}

func loadIdentity(dir string) (*identity, bool, error) {
	keyPEM, err := os.ReadFile(filepath.Join(dir, keyFile)) // #nosec G304 -- operator-controlled agent state dir, not network input
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, certFile)) // #nosec G304 -- operator-controlled agent state dir, not network input
	if err != nil {
		return nil, false, err
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, caFile)) // #nosec G304 -- operator-controlled agent state dir, not network input
	if err != nil {
		return nil, false, err
	}
	metaRaw, err := os.ReadFile(filepath.Join(dir, metaFile)) // #nosec G304 -- operator-controlled agent state dir, not network input
	if err != nil {
		return nil, false, err
	}
	var m meta
	if err := json.Unmarshal(metaRaw, &m); err != nil {
		return nil, false, err
	}
	return &identity{agentID: m.AgentID, relayAddr: m.RelayAddr, keyPEM: keyPEM, certPEM: certPEM, caPEM: caPEM}, true, nil
}

func enroll(ctx context.Context, env agentEnv) (*identity, error) {
	_, csrPEM, keyPEM, err := broker.GenerateAgentKey()
	if err != nil {
		return nil, err
	}
	reqBody, err := json.Marshal(broker.EnrollHTTPRequest{
		Token:        env.token,
		CSR:          string(csrPEM),
		AgentVersion: version,
		Platform:     platform(),
	})
	if err != nil {
		return nil, err
	}
	url := env.apiURL + "/api/v1/agents/enroll"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client, err := httpClient(env.apiCAFile)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("access-target-agent: enroll request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("access-target-agent: enroll failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out broker.EnrollHTTPResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("access-target-agent: decode enroll response: %w", err)
	}

	id := &identity{
		agentID:   out.AgentID,
		relayAddr: out.RelayAddr,
		keyPEM:    keyPEM,
		certPEM:   []byte(out.ClientCert),
		caPEM:     []byte(out.CACert),
	}
	if err := persistIdentity(env.stateDir, id, out.NotAfter); err != nil {
		return nil, err
	}
	logger.Infof(ctx, "access-target-agent: enrolled successfully agent=%s", out.AgentID)
	return id, nil
}

func persistIdentity(dir string, id *identity, notAfter time.Time) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	m, err := json.MarshalIndent(meta{AgentID: id.agentID, RelayAddr: id.relayAddr, NotAfter: notAfter}, "", "  ")
	if err != nil {
		return err
	}
	// Each file is written atomically (temp + rename) and the key is written
	// LAST. Rename is atomic on a POSIX filesystem and loadIdentity keys off the
	// key file's presence, so a crash mid-persist leaves either a complete,
	// loadable identity or no key at all (a clean re-enroll on next boot) — never
	// the half-written state that would otherwise wedge the agent until an
	// operator manually clears the state directory. 0600: key/cert are sensitive.
	writes := []struct {
		name string
		data []byte
	}{
		{certFile, id.certPEM},
		{caFile, id.caPEM},
		{metaFile, m},
		{keyFile, id.keyPEM},
	}
	for _, w := range writes {
		if err := atomicWriteFile(filepath.Join(dir, w.name), w.data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// atomicWriteFile writes data to a temp file in the same directory, fsyncs it,
// and renames it into place, so a reader never observes a partial file and a
// crash leaves the prior contents (or nothing) rather than a truncated one.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we fail before the rename; a no-op once renamed.
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func parseReachable(csv string) []broker.ReachableSpec {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return nil
	}
	var specs []broker.ReachableSpec
	for _, part := range strings.Split(csv, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		specs = append(specs, broker.ReachableSpec{Pattern: p, Kind: broker.ClassifyPattern(p)})
	}
	return specs
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// httpClient builds the enrollment HTTP client. When caFile is set its CA is
// added to the system roots so the agent can verify a control plane that uses a
// private/issuer CA for its public API; otherwise the system roots are used.
func httpClient(caFile string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile) // #nosec G304 -- operator-supplied trusted CA path, not network input
		if err != nil {
			return nil, fmt.Errorf("access-target-agent: read API CA: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("access-target-agent: no certificates in ACCESS_AGENT_API_CA_FILE")
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

func platform() string { return runtime.GOOS + "/" + runtime.GOARCH }
