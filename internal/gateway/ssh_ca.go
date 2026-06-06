package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHCertificateAuthority mints short-lived SSH user certificates so the
// gateway authenticates to a target host with an ephemeral, per-session
// certificate instead of a static private key kept on the target. The target's
// sshd trusts the CA public key (deployed out of band via TrustedUserCAKeys),
// so no long-lived gateway key is ever installed on the target. When a target
// does not trust the CA the proxy falls back to JIT credential injection
// (the vault-sealed Secret).
type SSHCertificateAuthority struct {
	caSigner ssh.Signer
	validity time.Duration
}

// defaultCertValidity bounds a minted cert's lifetime when none is configured.
const defaultCertValidity = 5 * time.Minute

// NewSSHCertificateAuthority wraps caSigner. validity caps each issued cert's
// lifetime (<= 0 selects 5 minutes).
func NewSSHCertificateAuthority(caSigner ssh.Signer, validity time.Duration) *SSHCertificateAuthority {
	if validity <= 0 {
		validity = defaultCertValidity
	}
	return &SSHCertificateAuthority{caSigner: caSigner, validity: validity}
}

// LoadSSHCAFromValue builds a CA from either inline PEM (value begins with
// "-----BEGIN") or a filesystem path to a PEM file. An empty value is rejected
// so the gateway falls back to credential injection rather than issuing certs
// from a zero-value CA.
func LoadSSHCAFromValue(valueOrPath string, validity time.Duration) (*SSHCertificateAuthority, error) {
	if strings.TrimSpace(valueOrPath) == "" {
		return nil, errors.New("gateway: ssh ca key is empty")
	}
	var pem []byte
	if strings.HasPrefix(strings.TrimSpace(valueOrPath), "-----BEGIN") {
		pem = []byte(strings.TrimSpace(valueOrPath))
	} else {
		// G304: valueOrPath is the operator-supplied path to the CA private key,
		// read once at boot — not attacker-controlled input.
		b, err := os.ReadFile(valueOrPath) // #nosec G304
		if err != nil {
			return nil, fmt.Errorf("gateway: read ssh ca key %s: %w", valueOrPath, err)
		}
		pem = b
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("gateway: parse ssh ca key: %w", err)
	}
	return NewSSHCertificateAuthority(signer, validity), nil
}

// LoadHostKeyFromValue parses the gateway's SSH server host key from either
// inline PEM (value begins with "-----BEGIN") or a filesystem path to a PEM
// file, mirroring LoadSSHCAFromValue. A stable host key keeps the listener's
// fingerprint constant across restarts so operators' SSH clients do not warn
// about a changed key; an empty value is rejected so the caller can fall back
// to an ephemeral key explicitly.
func LoadHostKeyFromValue(valueOrPath string) (ssh.Signer, error) {
	if strings.TrimSpace(valueOrPath) == "" {
		return nil, errors.New("gateway: ssh host key is empty")
	}
	var pem []byte
	if strings.HasPrefix(strings.TrimSpace(valueOrPath), "-----BEGIN") {
		pem = []byte(strings.TrimSpace(valueOrPath))
	} else {
		// G304: valueOrPath is the operator-supplied path to the host key, read
		// once at boot — not attacker-controlled input.
		b, err := os.ReadFile(valueOrPath) // #nosec G304
		if err != nil {
			return nil, fmt.Errorf("gateway: read ssh host key %s: %w", valueOrPath, err)
		}
		pem = b
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("gateway: parse ssh host key: %w", err)
	}
	return signer, nil
}

// Fingerprint returns the SHA-256 fingerprint of the CA public key. Operators
// copy this into a target's TrustedUserCAKeys to trust gateway-minted certs.
func (a *SSHCertificateAuthority) Fingerprint() string {
	if a == nil || a.caSigner == nil {
		return ""
	}
	return ssh.FingerprintSHA256(a.caSigner.PublicKey())
}

// MintEphemeralCert generates a fresh ed25519 keypair, signs it as a
// short-lived SSH user certificate for principal, and returns a cert signer
// ready to use as an upstream PublicKeys auth method. The cert is valid only
// for a few minutes and carries permit-pty so interactive shells work; nothing
// else is granted.
func (a *SSHCertificateAuthority) MintEphemeralCert(principal string) (ssh.Signer, error) {
	if a == nil || a.caSigner == nil {
		return nil, errors.New("gateway: SSHCertificateAuthority is nil")
	}
	if principal == "" {
		return nil, errors.New("gateway: empty principal for ssh cert")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gateway: generate ephemeral ed25519: %w", err)
	}
	ephemeral, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("gateway: ephemeral signer: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("gateway: ephemeral ssh public key: %w", err)
	}
	now := time.Now()
	cert := &ssh.Certificate{
		Key:             sshPub,
		Serial:          uint64(now.UnixNano()),
		CertType:        ssh.UserCert,
		KeyId:           fmt.Sprintf("pam-gateway:%s:%d", principal, now.UnixNano()),
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(now.Add(-30 * time.Second).Unix()),
		ValidBefore:     uint64(now.Add(a.validity).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{"permit-pty": ""},
		},
	}
	if err := cert.SignCert(rand.Reader, a.caSigner); err != nil {
		return nil, fmt.Errorf("gateway: sign ssh cert: %w", err)
	}
	certSigner, err := ssh.NewCertSigner(cert, ephemeral)
	if err != nil {
		return nil, fmt.Errorf("gateway: cert signer: %w", err)
	}
	return certSigner, nil
}
