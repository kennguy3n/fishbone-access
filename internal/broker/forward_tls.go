package broker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"time"
)

// Inter-replica mTLS trust boundary.
//
// The forward listener (forwarder.go) accepts replica-to-replica connections so
// one pam-gateway replica can ask the replica that owns an agent's tunnel to
// open a stream on its behalf. This identity is DELIBERATELY SEPARATE from the
// agent CA: replicas authenticate to EACH OTHER with their own CA, never with
// agent certificates. Mixing the two would let a leaked agent key reach the
// internal forward plane, or let a replica masquerade as an agent. Keeping the
// roots disjoint means the forward plane trusts exactly "another replica of this
// deployment" and nothing else.
//
// Hostname verification is pinned to a fixed identity name rather than the
// dialed host:port, because the owner's internal address (a pod IP, say) is
// dynamic and per-deployment. Every forward identity certificate carries
// forwardServerName as a SAN and the client always verifies against it, so
// mutual auth holds regardless of which internal address the owner advertises.
const forwardServerName = "shieldnet-access-forward"

// forwardCertTTL is the lifetime of an ephemeral forward identity certificate
// (dev/test). Production supplies long-lived operator-managed material.
const forwardCertTTL = 365 * 24 * time.Hour

// ForwardTLS holds the two TLS configs the forward plane needs: a server config
// for the owner's listener (requires + verifies a peer replica certificate) and
// a client config for the calling replica (presents its certificate, verifies
// the owner against the shared inter-replica CA). Both sides of a deployment are
// configured with the SAME inter-replica CA, so any replica can authenticate to
// any other.
type ForwardTLS struct {
	server *tls.Config
	client *tls.Config
}

// ServerConfig returns the listener-side mTLS config.
func (f *ForwardTLS) ServerConfig() *tls.Config { return f.server }

// ClientConfig returns the dialer-side mTLS config.
func (f *ForwardTLS) ClientConfig() *tls.Config { return f.client }

// LoadForwardTLS builds the inter-replica mTLS configs from operator-supplied
// PEM material (each argument is an inline PEM value or a path to one, resolved
// like the agent CA loader). cert/key are this replica's forward identity
// (signed by the inter-replica CA, valid for forwardServerName and usable for
// BOTH client and server auth); caValueOrPath is the inter-replica CA every
// replica trusts.
func LoadForwardTLS(certValueOrPath, keyValueOrPath, caValueOrPath string) (*ForwardTLS, error) {
	certPEM, err := resolvePEMValue(certValueOrPath)
	if err != nil {
		return nil, fmt.Errorf("broker: resolve forward certificate: %w", err)
	}
	keyPEM, err := resolvePEMValue(keyValueOrPath)
	if err != nil {
		return nil, fmt.Errorf("broker: resolve forward key: %w", err)
	}
	caPEM, err := resolvePEMValue(caValueOrPath)
	if err != nil {
		return nil, fmt.Errorf("broker: resolve forward CA: %w", err)
	}
	leaf, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("broker: load forward identity: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("broker: forward CA PEM contained no certificate")
	}
	return forwardTLSFrom(leaf, pool), nil
}

// NewEphemeralForwardTLS generates an in-memory inter-replica CA and a single
// forward identity signed by it (valid for both client and server auth), then
// builds the mTLS configs trusting that CA. It backs dev boots and tests where
// no forward material is configured; a multi-replica deployment supplies stable
// material via LoadForwardTLS so peers across pods/hosts share trust. The same
// *ForwardTLS can be shared by multiple in-process Relay instances in a test,
// which is exactly the cross-replica relay integration scenario.
func NewEphemeralForwardTLS() (*ForwardTLS, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: "ShieldNet Access Inter-Replica CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: forwardServerName},
		DNSNames:     []string{forwardServerName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(forwardCertTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// Both usages: each replica uses one identity as the listener (server)
		// and as the caller (client).
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	leaf := tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  leafKey,
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return forwardTLSFrom(leaf, pool), nil
}

// forwardTLSFrom assembles the server and client configs from a loaded identity
// and trust pool. Shared by both constructors so the security parameters
// (mutual auth, TLS 1.2 floor, pinned ServerName) are defined in one place.
func forwardTLSFrom(leaf tls.Certificate, pool *x509.CertPool) *ForwardTLS {
	return &ForwardTLS{
		server: &tls.Config{
			Certificates: []tls.Certificate{leaf},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pool,
			MinVersion:   tls.VersionTLS12,
		},
		client: &tls.Config{
			Certificates: []tls.Certificate{leaf},
			RootCAs:      pool,
			ServerName:   forwardServerName,
			MinVersion:   tls.VersionTLS12,
		},
	}
}
