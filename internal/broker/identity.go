package broker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Agent identity is an X.509 client certificate the control plane issues at
// enrollment and the relay verifies on every tunnel. The agent's UUID is the
// certificate Common Name and its workspace UUID is the single Organization
// entry, so the relay derives both from the verified peer certificate and never
// from anything the agent says on the wire. This mirrors the mTLS posture the
// rest of the platform uses for service-to-service identity (internal/iamcore,
// the AI A2A client): trust is the certificate, checked by the TLS stack
// against the agent CA, then bound to a database row by fingerprint.

// defaultCertTTL is the issued client-certificate lifetime when the caller does
// not override it. Short enough that a leaked agent key is not useful forever,
// long enough that a healthy agent is not re-enrolling constantly; the agent
// re-enrolls (operator re-issues a token) before expiry.
const defaultCertTTL = 720 * time.Hour // 30 days

// AgentCA signs agent client certificates. The relay only needs the CA
// certificate (to build a verify pool); the enrollment service needs the full
// CA (certificate + private key) to sign.
type AgentCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

// NewEphemeralCA generates an in-memory ECDSA P-256 CA. It backs dev and test
// boots (and the single-process demo) where no CA material is configured; a
// multi-process deployment configures a stable CA so the ztna-api signer and
// the pam-gateway relay share trust across restarts.
func NewEphemeralCA() (*AgentCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: "ShieldNet Access Agent CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &AgentCA{cert: cert, key: key, certPEM: pemBlock("CERTIFICATE", der)}, nil
}

// LoadCA parses a configured CA certificate + private key (both PEM) into a
// full signing CA. Used by the enrollment service (ztna-api).
func LoadCA(certPEM, keyPEM []byte) (*AgentCA, error) {
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("broker: parse CA certificate: %w", err)
	}
	keyDER, _ := pem.Decode(keyPEM)
	if keyDER == nil {
		return nil, errors.New("broker: CA key PEM contains no block")
	}
	key, err := parseECKey(keyDER.Bytes)
	if err != nil {
		return nil, fmt.Errorf("broker: parse CA key: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("broker: configured CA certificate is not a CA")
	}
	return &AgentCA{cert: cert, key: key, certPEM: pemBlock("CERTIFICATE", cert.Raw)}, nil
}

// LoadCAFromValues resolves the CA certificate and key, each of which may be an
// inline PEM value (begins with "-----BEGIN") or a path to a PEM file, then
// builds the signing CA. This mirrors the gateway's LoadSSHCAFromValue posture
// so operators configure agent CA material the same way as the SSH CA.
func LoadCAFromValues(certValueOrPath, keyValueOrPath string) (*AgentCA, error) {
	certPEM, err := resolvePEMValue(certValueOrPath)
	if err != nil {
		return nil, fmt.Errorf("broker: resolve CA certificate: %w", err)
	}
	keyPEM, err := resolvePEMValue(keyValueOrPath)
	if err != nil {
		return nil, fmt.Errorf("broker: resolve CA key: %w", err)
	}
	return LoadCA(certPEM, keyPEM)
}

// resolvePEMValue returns the bytes of an inline PEM value or the contents of
// the file it names.
func resolvePEMValue(valueOrPath string) ([]byte, error) {
	trimmed := strings.TrimSpace(valueOrPath)
	if trimmed == "" {
		return nil, errors.New("broker: empty PEM value")
	}
	if strings.HasPrefix(trimmed, "-----BEGIN") {
		return []byte(valueOrPath), nil
	}
	b, err := os.ReadFile(trimmed) // #nosec G304 -- operator-supplied trusted path, same posture as the SSH CA loader
	if err != nil {
		return nil, err
	}
	return b, nil
}

// CertPEM returns the CA certificate in PEM form (handed to the agent at
// enrollment so it can verify the relay's server certificate).
func (ca *AgentCA) CertPEM() []byte { return ca.certPEM }

// Pool returns a cert pool trusting this CA, for verifying agent client certs
// (relay) or the relay server cert (agent).
func (ca *AgentCA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}

// IssuedCert is the result of signing one agent client certificate.
type IssuedCert struct {
	CertPEM     []byte
	Fingerprint string
	Serial      string
	NotAfter    time.Time
}

// SignAgentCertFromCSR verifies the CSR's self-signature (proof the agent holds
// the private key) and issues a client certificate binding agentID (CommonName)
// and workspaceID (Organization) to the CSR's public key. The CSR's own subject
// is ignored: identity is assigned by the control plane, never self-asserted.
func (ca *AgentCA) SignAgentCertFromCSR(csrPEM []byte, agentID, workspaceID uuid.UUID, ttl time.Duration) (*IssuedCert, error) {
	if ca.key == nil {
		return nil, errors.New("broker: CA has no signing key (verify-only)")
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("broker: CSR PEM contains no block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("broker: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("broker: CSR signature invalid: %w", err)
	}
	if ttl <= 0 {
		ttl = defaultCertTTL
	}
	notAfter := time.Now().Add(ttl)
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject: pkix.Name{
			CommonName:   agentID.String(),
			Organization: []string{workspaceID.String()},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("broker: sign certificate: %w", err)
	}
	return &IssuedCert{
		CertPEM:     pemBlock("CERTIFICATE", der),
		Fingerprint: Fingerprint(der),
		Serial:      tmpl.SerialNumber.String(),
		NotAfter:    notAfter,
	}, nil
}

// IssueServerCert signs a TLS SERVER certificate for the relay listener, valid
// for the given hostnames/IPs, so agents (which trust the agent CA) verify the
// relay they dial out to. The relay and the agents thus share one trust root.
func (ca *AgentCA) IssueServerCert(hosts []string, ttl time.Duration) (tls.Certificate, error) {
	if ca.key == nil {
		return tls.Certificate{}, errors.New("broker: CA has no signing key (verify-only)")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	if ttl <= 0 {
		ttl = defaultCertTTL
	}
	tmpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: "ShieldNet Access Relay"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(pemBlock("CERTIFICATE", der), pemBlock("PRIVATE KEY", keyDER))
}

// AgentIdentity is the verified identity carried by an agent client cert.
type AgentIdentity struct {
	AgentID     uuid.UUID
	WorkspaceID uuid.UUID
	Fingerprint string
}

// IdentityFromCert extracts and validates the agent and workspace UUIDs from a
// verified peer certificate. It fails closed when either is missing or
// malformed so a certificate the relay cannot attribute to a tenant is never
// allowed to broker.
func IdentityFromCert(cert *x509.Certificate) (AgentIdentity, error) {
	if cert == nil {
		return AgentIdentity{}, errors.New("broker: no peer certificate")
	}
	agentID, err := uuid.Parse(cert.Subject.CommonName)
	if err != nil {
		return AgentIdentity{}, fmt.Errorf("broker: certificate CN is not an agent id: %w", err)
	}
	if len(cert.Subject.Organization) == 0 {
		return AgentIdentity{}, errors.New("broker: certificate carries no workspace organization")
	}
	wsID, err := uuid.Parse(cert.Subject.Organization[0])
	if err != nil {
		return AgentIdentity{}, fmt.Errorf("broker: certificate O is not a workspace id: %w", err)
	}
	return AgentIdentity{AgentID: agentID, WorkspaceID: wsID, Fingerprint: Fingerprint(cert.Raw)}, nil
}

// Fingerprint is the lowercase hex SHA-256 of a certificate's DER bytes, used as
// the stable identifier persisted on the agent row and matched on connect.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func newSerial() *big.Int {
	// 128-bit random serial. crypto/rand failure is treated as fatal-to-issue by
	// callers (CreateCertificate would also fail); fall back to a time-based
	// serial only to keep the function total.
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return n
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func parseCertPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// parseECKey accepts either SEC1 ("EC PRIVATE KEY") or PKCS#8 encodings so an
// operator can supply whichever their tooling emits.
func parseECKey(der []byte) (*ecdsa.PrivateKey, error) {
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an ECDSA private key")
	}
	return ec, nil
}
