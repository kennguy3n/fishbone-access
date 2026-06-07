package aiclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// mTLS environment variables for the Go-side A2A client. They mirror the
// Python agent's server-side variables (cmd/access-ai-agent/mtls.py) so a
// single shared contract configures both ends:
//
//	client cert/key   →  the agent's A2A_MTLS_CLIENT_CA_FILE verifies us
//	A2A_MTLS_CA_FILE  →  verifies the agent's server cert
//	expected identity →  pins the agent's SPIFFE URI-SAN (defence in depth
//	                     over hostname verification)
//
// All four cert-related variables MUST be set together. A half-configured
// client (some but not all of cert/key/ca) is a boot-time error rather than a
// silent fall-through to a plaintext or server-unauthenticated connection,
// matching the fail-closed posture of mtls.py's ServerConfig.
const (
	// EnvClientCertFile is the PEM client certificate the agent verifies.
	EnvClientCertFile = "A2A_MTLS_CLIENT_CERT_FILE"
	// EnvClientKeyFile is the PEM private key for the client certificate.
	EnvClientKeyFile = "A2A_MTLS_CLIENT_KEY_FILE"
	// EnvServerCAFile is the PEM CA bundle that signs the agent's server
	// certificate. Used as the client's RootCAs.
	EnvServerCAFile = "A2A_MTLS_CA_FILE"
	// EnvServerName overrides the SNI / hostname verified in the agent's
	// server certificate. Defaults to the host parsed from the base URL.
	EnvServerName = "A2A_MTLS_SERVER_NAME"
	// EnvExpectedServerIdentity is a comma-separated allowlist of SPIFFE
	// URI-SANs the agent's server certificate must present at least one of.
	// When empty, only standard chain + hostname verification applies.
	EnvExpectedServerIdentity = "A2A_MTLS_EXPECTED_SERVER_IDENTITY"
	// EnvBaseURL is the agent root URL, e.g.
	// https://access-ai-agent.internal:8443.
	EnvBaseURL = "ACCESS_AI_AGENT_URL"
	// EnvAPIKey is the optional shared secret sent as X-API-Key for
	// defence-in-depth alongside mTLS.
	EnvAPIKey = "ACCESS_AI_AGENT_API_KEY"
)

// MTLSConfigError signals a half-configured or unreadable mTLS configuration.
// It is returned at construction time so a misconfiguration fails the boot
// rather than degrading to an unauthenticated transport at request time.
type MTLSConfigError struct{ msg string }

func (e *MTLSConfigError) Error() string { return "aiclient: " + e.msg }

// ClientTLSConfig is the resolved, validated mTLS material for the client.
type ClientTLSConfig struct {
	ClientCertFile string
	ClientKeyFile  string
	ServerCAFile   string
	ServerName     string
	// ExpectedServerIdentities is the SPIFFE URI-SAN allowlist the agent's
	// server certificate is pinned against (empty = hostname-only).
	ExpectedServerIdentities []string
}

// TLSConfigFromEnv reads the client mTLS configuration from the process
// environment. It returns (nil, nil) when NONE of the cert variables are set
// (the caller then runs without a configured agent and its fallback path
// fires), a *MTLSConfigError when the configuration is partial or unreadable,
// and a ready-to-use config otherwise.
func TLSConfigFromEnv() (*ClientTLSConfig, error) {
	cfg := &ClientTLSConfig{
		ClientCertFile:           strings.TrimSpace(os.Getenv(EnvClientCertFile)),
		ClientKeyFile:            strings.TrimSpace(os.Getenv(EnvClientKeyFile)),
		ServerCAFile:             strings.TrimSpace(os.Getenv(EnvServerCAFile)),
		ServerName:               strings.TrimSpace(os.Getenv(EnvServerName)),
		ExpectedServerIdentities: parseIdentities(os.Getenv(EnvExpectedServerIdentity)),
	}
	if !cfg.hasAnyField() {
		return nil, nil
	}
	if !cfg.isComplete() {
		return nil, &MTLSConfigError{msg: fmt.Sprintf(
			"mTLS is half-configured: set all of %s, %s, %s together (or none)",
			EnvClientCertFile, EnvClientKeyFile, EnvServerCAFile,
		)}
	}
	return cfg, nil
}

// hasAnyField reports whether at least one cert path is set.
func (c *ClientTLSConfig) hasAnyField() bool {
	return c.ClientCertFile != "" || c.ClientKeyFile != "" || c.ServerCAFile != ""
}

// isComplete reports whether all three cert paths are set.
func (c *ClientTLSConfig) isComplete() bool {
	return c.ClientCertFile != "" && c.ClientKeyFile != "" && c.ServerCAFile != ""
}

// Build constructs a *tls.Config for the client: it presents the client
// certificate (so the agent can verify us), trusts only the configured CA for
// the server certificate, floors the protocol at TLS 1.3 (matching the Python
// server), and — when an identity allowlist is configured — pins the server's
// SPIFFE URI-SAN via VerifyPeerCertificate as a defence-in-depth layer over
// hostname verification.
func (c *ClientTLSConfig) Build() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(c.ClientCertFile, c.ClientKeyFile)
	if err != nil {
		return nil, &MTLSConfigError{msg: "load client cert/key: " + err.Error()}
	}
	caPEM, err := os.ReadFile(c.ServerCAFile)
	if err != nil {
		return nil, &MTLSConfigError{msg: "read server CA: " + err.Error()}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, &MTLSConfigError{msg: "server CA file contained no PEM certificates"}
	}
	tc := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
		ServerName:   c.ServerName,
	}
	if len(c.ExpectedServerIdentities) > 0 {
		allow := append([]string(nil), c.ExpectedServerIdentities...)
		tc.VerifyPeerCertificate = makeURISANVerifier(allow)
	}
	return tc, nil
}

// makeURISANVerifier returns a VerifyPeerCertificate callback that requires the
// leaf certificate (verifiedChains[0][0]) to carry at least one URI-SAN in the
// allowlist. The standard library has already verified the chain against RootCAs
// and the hostname by the time this runs, so this is an additional identity
// gate, never a replacement for chain verification.
func makeURISANVerifier(allow []string) func([][]byte, [][]*x509.Certificate) error {
	allowSet := make(map[string]struct{}, len(allow))
	for _, a := range allow {
		allowSet[a] = struct{}{}
	}
	return func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
			return &MTLSConfigError{msg: "no verified certificate chain presented by server"}
		}
		leaf := verifiedChains[0][0]
		for _, u := range leaf.URIs {
			if _, ok := allowSet[u.String()]; ok {
				return nil
			}
		}
		return &MTLSConfigError{msg: fmt.Sprintf(
			"server certificate URI-SANs %v match none of the expected identities %v",
			uriStrings(leaf.URIs), allow,
		)}
	}
}

func uriStrings(uris []*url.URL) []string {
	out := make([]string, 0, len(uris))
	for _, u := range uris {
		out = append(out, u.String())
	}
	return out
}

// parseIdentities splits a comma-separated allowlist, trimming blanks.
func parseIdentities(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
