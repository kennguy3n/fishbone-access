package broker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"testing"
	"time"
)

// interReplicaPEM mints an inter-replica CA and one identity (valid for both
// client and server auth, CN/SAN = forwardServerName) and returns them as PEM,
// mirroring what an operator supplies to LoadForwardTLS in production.
func interReplicaPEM(t *testing.T) (certPEM, keyPEM, caPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: "test inter-replica CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: forwardServerName},
		DNSNames:              []string{forwardServerName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER})
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return certPEM, keyPEM, caPEM
}

// TestLoadForwardTLSArgOrder pins the (cert, key, ca) argument order of
// LoadForwardTLS: the correct order loads and completes a mutual-auth handshake,
// while the (ca, cert, key) mis-order — the exact wiring bug Devin Review caught
// in pam-gateway — must fail fast at load (a certificate PEM is not a key), so a
// future caller cannot silently reintroduce it.
func TestLoadForwardTLSArgOrder(t *testing.T) {
	certPEM, keyPEM, caPEM := interReplicaPEM(t)

	ftls, err := LoadForwardTLS(string(certPEM), string(keyPEM), string(caPEM))
	if err != nil {
		t.Fatalf("LoadForwardTLS(cert, key, ca) must succeed, got: %v", err)
	}
	assertForwardHandshake(t, ftls)

	if _, err := LoadForwardTLS(string(caPEM), string(certPEM), string(keyPEM)); err == nil {
		t.Fatalf("LoadForwardTLS with (ca, cert, key) mis-order must fail, got nil")
	}
}

// assertForwardHandshake proves the loaded configs actually interoperate: a
// client dials the server over the inter-replica mTLS and both directions of a
// byte exchange complete.
func assertForwardHandshake(t *testing.T, ftls *ForwardTLS) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", ftls.ServerConfig())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srvErr := make(chan error, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			srvErr <- aerr
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, rerr := conn.Read(buf); rerr != nil {
			srvErr <- rerr
			return
		}
		_, werr := conn.Write(buf)
		srvErr <- werr
	}()

	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", ln.Addr().String(), ftls.ClientConfig())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 4)
	if _, err := conn.Read(got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("echo = %q, want %q", got, "ping")
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}
