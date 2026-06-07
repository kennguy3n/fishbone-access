//go:build integration

// Package aiclient integration test: drives the real Python access-ai-agent
// over mutual TLS using the real Go client, exercising the full A2A contract
// end-to-end across the language boundary.
//
// Run with:  go test -tags=integration ./internal/pkg/aiclient/ -run Python
//
// It is build-tagged so the default `go test ./...` (and the race job) never
// depend on a Python toolchain; it self-skips when python3 or the agent's
// dependencies are unavailable.
package aiclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
)

// safeBuffer is a goroutine-safe buffer: the child process writes to it from
// os/exec's copier goroutine while the test goroutine may read it on failure.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func itoa(i int) string { return strconv.Itoa(i) }

const (
	pyServerIdentity = "spiffe://shieldnet/access/ai-agent"
	pyClientIdentity = "spiffe://shieldnet/access/workflow-engine"
)

type pyTestCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newPyCA(t *testing.T) *pyTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "shieldnet-it-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return &pyTestCA{key: key, cert: cert}
}

// issue writes a leaf cert+key to dir and returns their paths.
func (ca *pyTestCA) issue(t *testing.T, dir, cn string, dns []string, ips []net.IP, uris []string, server bool) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	parsed := make([]*url.URL, 0, len(uris))
	for _, u := range uris {
		pu, perr := url.Parse(u)
		if perr != nil {
			t.Fatalf("parse uri %q: %v", u, perr)
		}
		parsed = append(parsed, pu)
	}
	usage := x509.ExtKeyUsageClientAuth
	if server {
		usage = x509.ExtKeyUsageServerAuth
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     dns,
		IPAddresses:  ips,
		URIs:         parsed,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPath = filepath.Join(dir, cn+".crt")
	keyPath = filepath.Join(dir, cn+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func (ca *pyTestCA) writeCA(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	return p
}

func agentDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// internal/pkg/aiclient/<file> → repo root is three levels up.
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
	return filepath.Join(root, "cmd", "access-ai-agent")
}

func skipUnlessPython(t *testing.T, dir string) string {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found; skipping Go↔Python integration test")
	}
	check := exec.Command(py, "-c", "import fastapi, uvicorn, httpx, cryptography")
	check.Dir = dir
	if out, err := check.CombinedOutput(); err != nil {
		t.Skipf("agent python deps unavailable (%v): %s", err, out)
	}
	return py
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestPythonAgentEndToEndMTLS(t *testing.T) {
	dir := agentDir(t)
	py := skipUnlessPython(t, dir)

	tmp := t.TempDir()
	ca := newPyCA(t)
	caFile := ca.writeCA(t, tmp)
	srvCert, srvKey := ca.issue(t, tmp, "server", []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, []string{pyServerIdentity}, true)
	cliCert, cliKey := ca.issue(t, tmp, "client", nil, nil, []string{pyClientIdentity}, false)

	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, py, "main.py")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"A2A_MTLS_SERVER_CERT_FILE="+srvCert,
		"A2A_MTLS_SERVER_KEY_FILE="+srvKey,
		"A2A_MTLS_CLIENT_CA_FILE="+caFile,
		"A2A_MTLS_EXPECTED_CLIENT_IDENTITY="+pyClientIdentity,
		"ACCESS_AI_AGENT_HOST=127.0.0.1",
		"ACCESS_AI_AGENT_PORT="+itoa(port),
		"ACCESS_AI_LLM_PROVIDER=", // deterministic
	)
	var logs safeBuffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("start agent: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("agent logs:\n%s", logs.String())
		}
	})

	tc, err := (&ClientTLSConfig{
		ClientCertFile:           cliCert,
		ClientKeyFile:            cliKey,
		ServerCAFile:             caFile,
		ServerName:               "localhost",
		ExpectedServerIdentities: []string{pyServerIdentity},
	}).Build()
	if err != nil {
		t.Fatalf("build client tls: %v", err)
	}
	client := NewAIClient("https://localhost:"+itoa(port), tc, "")

	// Poll until the agent is serving (TLS handshake + skill round-trip).
	var resp *SkillResponse
	deadline := time.Now().Add(20 * time.Second)
	for {
		callCtx, callCancel := context.WithTimeout(ctx, 2*time.Second)
		resp, err = client.InvokeSkill(callCtx, SkillAccessRiskAssessment, map[string]any{
			"role":                 "admin",
			"resource_external_id": "db-prod",
		})
		callCancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent never became ready: %v\nlogs:\n%s", err, logs.String())
		}
		time.Sleep(200 * time.Millisecond)
	}

	if resp.RiskScore != "high" {
		t.Errorf("risk_score = %q; want high (admin on prod)\nfull: %+v", resp.RiskScore, resp)
	}
	if len(resp.RiskFactors) == 0 {
		t.Errorf("expected risk_factors to be populated; got %+v", resp)
	}

	// A second, lower-risk request must produce a different, lower score —
	// proving the response is a function of the payload, not a constant.
	low, err := client.InvokeSkill(ctx, SkillAccessRiskAssessment, map[string]any{
		"role":                 "viewer",
		"resource_external_id": "wiki",
		"justification":        "on-call runbook",
	})
	if err != nil {
		t.Fatalf("second invoke: %v", err)
	}
	if low.RiskScore != "low" {
		t.Errorf("risk_score = %q; want low (read-only with justification)", low.RiskScore)
	}
}
