package aiclient

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestTLSConfigFromEnv_NoneSet_ReturnsNil(t *testing.T) {
	clearMTLSEnv(t)
	cfg, err := TLSConfigFromEnv()
	if err != nil {
		t.Fatalf("err = %v; want nil", err)
	}
	if cfg != nil {
		t.Errorf("cfg = %+v; want nil when nothing configured", cfg)
	}
}

func TestTLSConfigFromEnv_HalfConfigured_Errors(t *testing.T) {
	clearMTLSEnv(t)
	t.Setenv(EnvClientCertFile, "/tmp/cert.pem")
	// key + CA intentionally missing
	_, err := TLSConfigFromEnv()
	var mErr *MTLSConfigError
	if !errors.As(err, &mErr) {
		t.Fatalf("err = %v; want *MTLSConfigError for half-configured mTLS", err)
	}
}

func TestParseIdentities(t *testing.T) {
	got := parseIdentities("a, b ,, c")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("parseIdentities len = %d; want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("identity[%d] = %q; want %q", i, got[i], want[i])
		}
	}
	if parseIdentities("   ") != nil {
		t.Error("blank input should parse to nil")
	}
}

func TestBuild_EndToEndWithRealCerts(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	certPath, keyPath := ca.issuePEMFiles(t, dir, "client", []string{testClientURI}, false)
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, ca.certPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	cfg := &ClientTLSConfig{
		ClientCertFile:           certPath,
		ClientKeyFile:            keyPath,
		ServerCAFile:             caPath,
		ServerName:               "access-ai-agent",
		ExpectedServerIdentities: []string{testServerURI},
	}
	tc, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if tc.MinVersion != 0x0304 { // TLS 1.3
		t.Errorf("MinVersion = %x; want TLS1.3", tc.MinVersion)
	}
	if len(tc.Certificates) != 1 {
		t.Errorf("expected 1 client certificate, got %d", len(tc.Certificates))
	}
	if tc.VerifyPeerCertificate == nil {
		t.Error("expected VerifyPeerCertificate to be set when identities configured")
	}
}

func TestBuild_BadCAFile(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	certPath, keyPath := ca.issuePEMFiles(t, dir, "client", nil, false)
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	cfg := &ClientTLSConfig{ClientCertFile: certPath, ClientKeyFile: keyPath, ServerCAFile: caPath}
	if _, err := cfg.Build(); err == nil {
		t.Fatal("expected error for CA file with no PEM certs")
	}
}

func clearMTLSEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{EnvClientCertFile, EnvClientKeyFile, EnvServerCAFile, EnvServerName, EnvExpectedServerIdentity, EnvBaseURL, EnvAPIKey} {
		t.Setenv(k, "")
	}
}

// setRealMTLSEnv writes an in-test CA + client leaf to a temp dir and points the
// three mTLS env vars at them, so TLSConfigFromEnv().Build() succeeds.
func setRealMTLSEnv(t *testing.T) {
	t.Helper()
	ca := newTestCA(t)
	dir := t.TempDir()
	certPath, keyPath := ca.issuePEMFiles(t, dir, "client", []string{testClientURI}, false)
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, ca.certPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	t.Setenv(EnvClientCertFile, certPath)
	t.Setenv(EnvClientKeyFile, keyPath)
	t.Setenv(EnvServerCAFile, caPath)
}

func TestNewAIClientFromEnv_CertsWithoutURL_Errors(t *testing.T) {
	clearMTLSEnv(t)
	setRealMTLSEnv(t)
	// EnvBaseURL intentionally left empty: a half-configured setup (mTLS material
	// provisioned but no agent URL) must fail closed rather than silently yield
	// an unconfigured client.
	var mErr *MTLSConfigError
	if _, err := NewAIClientFromEnv(); !errors.As(err, &mErr) {
		t.Fatalf("err = %v; want *MTLSConfigError when certs are set but %s is empty", err, EnvBaseURL)
	}
}

func TestNewAIClientFromEnv_CertsWithURL_Configured(t *testing.T) {
	clearMTLSEnv(t)
	setRealMTLSEnv(t)
	t.Setenv(EnvBaseURL, "https://access-ai-agent.internal:8443")
	c, err := NewAIClientFromEnv()
	if err != nil {
		t.Fatalf("NewAIClientFromEnv: %v", err)
	}
	if !c.Configured() {
		t.Error("client with mTLS material and a base URL should report configured")
	}
}

func TestNewAIClientFromEnv_NothingSet_Unconfigured(t *testing.T) {
	clearMTLSEnv(t)
	c, err := NewAIClientFromEnv()
	if err != nil {
		t.Fatalf("NewAIClientFromEnv: %v", err)
	}
	if c.Configured() {
		t.Error("client should be unconfigured when neither URL nor mTLS is set")
	}
}
