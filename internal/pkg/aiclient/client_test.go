package aiclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

const (
	testServerURI = "spiffe://shieldnet/access-ai-agent"
	testClientURI = "spiffe://shieldnet/access-control-plane"
)

// mtlsServer spins up an httptest TLS server requiring client certs signed by
// ca, serving the given handler. It returns the server and a *tls.Config the
// client can use to dial it (trusting ca, presenting a client cert with
// testClientURI).
func mtlsServer(t *testing.T, ca *testCA, handler http.Handler) (*httptest.Server, *tls.Config) {
	t.Helper()
	serverCert := ca.issue(t, "access-ai-agent", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, []string{testServerURI}, true)
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    ca.pool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	clientCert := ca.issue(t, "access-control-plane", nil, nil, []string{testClientURI}, false)
	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      ca.pool(),
		MinVersion:   tls.VersionTLS13,
		ServerName:   "localhost",
	}
	return srv, clientTLS
}

func newClientFor(srv *httptest.Server, clientTLS *tls.Config, apiKey string) *AIClient {
	c := NewAIClient(srv.URL, clientTLS, apiKey)
	c.SetHTTPClient(&http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}})
	return c
}

func TestInvokeSkill_MTLSHandshake_RoundTrip(t *testing.T) {
	ca := newTestCA(t)
	var gotSkill, gotTier, gotAPIKey string
	var gotClientURI string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) > 0 && len(r.TLS.PeerCertificates[0].URIs) > 0 {
			gotClientURI = r.TLS.PeerCertificates[0].URIs[0].String()
		}
		gotAPIKey = r.Header.Get("X-API-Key")
		var req invokeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		gotSkill = req.SkillName
		gotTier = req.WorkspaceAITier
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SkillResponse{RiskScore: "high", RiskFactors: []string{"sensitive_resource"}})
	})
	srv, clientTLS := mtlsServer(t, ca, handler)
	c := newClientFor(srv, clientTLS, "secret-key")

	resp, err := c.InvokeSkillForTier(context.Background(), SkillAccessRiskAssessment, "local_8b", RiskAssessmentInput{Role: "admin"})
	if err != nil {
		t.Fatalf("InvokeSkillForTier: %v", err)
	}
	if resp.RiskScore != "high" {
		t.Errorf("RiskScore = %q; want high", resp.RiskScore)
	}
	if gotSkill != SkillAccessRiskAssessment {
		t.Errorf("server saw skill %q; want %q", gotSkill, SkillAccessRiskAssessment)
	}
	if gotTier != "local_8b" {
		t.Errorf("server saw tier %q; want local_8b", gotTier)
	}
	if gotAPIKey != "secret-key" {
		t.Errorf("server saw api key %q; want secret-key", gotAPIKey)
	}
	if gotClientURI != testClientURI {
		t.Errorf("server saw client URI %q; want %q (client cert not presented)", gotClientURI, testClientURI)
	}
}

func TestInvokeSkill_ServerRejectsUnknownClientCA(t *testing.T) {
	ca := newTestCA(t)
	otherCA := newTestCA(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(SkillResponse{})
	})
	srv, _ := mtlsServer(t, ca, handler)

	// Client presents a cert signed by a CA the server does not trust.
	rogueCert := otherCA.issue(t, "rogue", nil, nil, []string{"spiffe://evil/rogue"}, false)
	rogueTLS := &tls.Config{
		Certificates: []tls.Certificate{rogueCert},
		RootCAs:      ca.pool(),
		MinVersion:   tls.VersionTLS13,
		ServerName:   "localhost",
	}
	c := newClientFor(srv, rogueTLS, "")
	_, err := c.InvokeSkill(context.Background(), SkillAccessRiskAssessment, nil)
	if err == nil {
		t.Fatal("expected handshake failure when server rejects untrusted client cert")
	}
}

func TestInvokeSkill_ClientRejectsUntrustedServer(t *testing.T) {
	ca := newTestCA(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(SkillResponse{})
	})
	srv, clientTLS := mtlsServer(t, ca, handler)

	// Client trusts a DIFFERENT CA than the one that signed the server cert.
	clientTLS.RootCAs = newTestCA(t).pool()
	c := newClientFor(srv, clientTLS, "")
	_, err := c.InvokeSkill(context.Background(), SkillAccessRiskAssessment, nil)
	if err == nil {
		t.Fatal("expected client to reject server cert signed by untrusted CA")
	}
}

func TestURISANVerifier_PinsServerIdentity(t *testing.T) {
	ca := newTestCA(t)
	leaf := ca.issue(t, "access-ai-agent", []string{"localhost"}, nil, []string{testServerURI}, true)
	x509Leaf, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	chains := [][]*x509.Certificate{{x509Leaf}}

	if err := makeURISANVerifier([]string{testServerURI})(nil, chains); err != nil {
		t.Errorf("verifier rejected matching identity: %v", err)
	}
	if err := makeURISANVerifier([]string{"spiffe://shieldnet/other"})(nil, chains); err == nil {
		t.Error("verifier accepted non-matching identity")
	}
	if err := makeURISANVerifier([]string{testServerURI})(nil, nil); err == nil {
		t.Error("verifier accepted empty chain")
	}
}

func TestInvokeSkill_IdentityPinningEndToEnd(t *testing.T) {
	ca := newTestCA(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(SkillResponse{RiskScore: "low"})
	})
	srv, clientTLS := mtlsServer(t, ca, handler)

	// Pin to the WRONG identity → VerifyPeerCertificate must fail the dial.
	clientTLS.VerifyPeerCertificate = makeURISANVerifier([]string{"spiffe://shieldnet/not-the-agent"})
	c := newClientFor(srv, clientTLS, "")
	if _, err := c.InvokeSkill(context.Background(), SkillAccessRiskAssessment, nil); err == nil {
		t.Fatal("expected identity-pinning failure for wrong SPIFFE id")
	}

	// Pin to the correct identity → succeeds.
	clientTLS.VerifyPeerCertificate = makeURISANVerifier([]string{testServerURI})
	c2 := newClientFor(srv, clientTLS, "")
	if _, err := c2.InvokeSkill(context.Background(), SkillAccessRiskAssessment, nil); err != nil {
		t.Fatalf("expected success with correct SPIFFE id, got %v", err)
	}
}

func TestInvokeSkill_Non200Error(t *testing.T) {
	ca := newTestCA(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	srv, clientTLS := mtlsServer(t, ca, handler)
	c := newClientFor(srv, clientTLS, "")
	_, err := c.InvokeSkill(context.Background(), SkillAccessRiskAssessment, nil)
	if err == nil {
		t.Fatal("expected error on HTTP 500")
	}
}

func TestInvokeSkill_Unconfigured(t *testing.T) {
	c := NewAIClient("", nil, "")
	if c.Configured() {
		t.Error("empty-baseURL client should report not configured")
	}
	_, err := c.InvokeSkill(context.Background(), SkillAccessRiskAssessment, nil)
	if !errors.Is(err, ErrAIUnconfigured) {
		t.Errorf("err = %v; want ErrAIUnconfigured", err)
	}
}

func TestInvokeSkillInto_RejectsBadOut(t *testing.T) {
	ca := newTestCA(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(SkillResponse{})
	})
	srv, clientTLS := mtlsServer(t, ca, handler)
	c := newClientFor(srv, clientTLS, "")

	if err := c.InvokeSkillInto(context.Background(), SkillAccessRiskAssessment, "", nil, nil); err == nil {
		t.Error("expected error for nil out")
	}
	var notPtr SkillResponse
	if err := c.InvokeSkillInto(context.Background(), SkillAccessRiskAssessment, "", nil, notPtr); err == nil {
		t.Error("expected error for non-pointer out")
	}
}

func TestTimeoutFromEnv(t *testing.T) {
	cases := []struct {
		name    string
		val     string
		set     bool
		want    time.Duration
		wantErr bool
	}{
		{name: "unset_defaults", set: false, want: defaultTimeout},
		{name: "empty_defaults", set: true, val: "", want: defaultTimeout},
		{name: "override_lower", set: true, val: "5s", want: 5 * time.Second},
		{name: "override_higher", set: true, val: "20s", want: 20 * time.Second},
		{name: "malformed_errors", set: true, val: "10", wantErr: true},
		{name: "zero_errors", set: true, val: "0s", wantErr: true},
		{name: "negative_errors", set: true, val: "-1s", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv(EnvTimeout, tc.val)
			} else {
				_ = os.Unsetenv(EnvTimeout)
			}
			got, err := timeoutFromEnv()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("timeoutFromEnv(%q) = %v; want error", tc.val, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("timeoutFromEnv(%q) unexpected error: %v", tc.val, err)
			}
			if got != tc.want {
				t.Errorf("timeoutFromEnv(%q) = %v; want %v", tc.val, got, tc.want)
			}
		})
	}
}

func TestNewAIClientFromEnv_RejectsBadTimeout(t *testing.T) {
	clearMTLSEnv(t)
	t.Setenv(EnvTimeout, "not-a-duration")
	if _, err := NewAIClientFromEnv(); err == nil {
		t.Fatal("expected error for malformed ACCESS_AI_AGENT_TIMEOUT")
	}
}
