package generic_oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted from a no-network test path")
}

func validConfig(issuer string) map[string]interface{} {
	return map[string]interface{}{
		"issuer_url":   issuer,
		"display_name": "Example OIDC IdP",
	}
}

func validSecrets() map[string]interface{} {
	return map[string]interface{}{
		"client_id":     "rp-id",
		"client_secret": "rp-secret",
	}
}

func TestValidate_HappyPath(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig("https://accounts.example.com"), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_MissingFields(t *testing.T) {
	c := New()
	cases := []struct {
		name    string
		cfg     map[string]interface{}
		secrets map[string]interface{}
	}{
		{"missing issuer", map[string]interface{}{"display_name": "x"}, validSecrets()},
		{"bad issuer", map[string]interface{}{"issuer_url": "not a url", "display_name": "x"}, validSecrets()},
		{"non-http issuer", map[string]interface{}{"issuer_url": "ldap://accounts.example.com", "display_name": "x"}, validSecrets()},
		{"missing display_name", map[string]interface{}{"issuer_url": "https://accounts.example.com"}, validSecrets()},
		{"missing client_id", validConfig("https://accounts.example.com"), map[string]interface{}{"client_secret": "rp-secret"}},
		{"missing client_secret", validConfig("https://accounts.example.com"), map[string]interface{}{"client_id": "rp-id"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := c.Validate(context.Background(), tc.cfg, tc.secrets); err == nil {
				t.Fatalf("Validate(%s) expected error", tc.name)
			}
		})
	}
}

func TestValidate_DoesNotMakeNetworkCalls(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })

	c := New()
	if err := c.Validate(context.Background(), validConfig("https://accounts.example.com"), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestRegistryIntegration(t *testing.T) {
	got, err := access.GetAccessConnector(ProviderName)
	if err != nil {
		t.Fatalf("GetAccessConnector(%q): %v", ProviderName, err)
	}
	if _, ok := got.(*GenericOIDCAccessConnector); !ok {
		t.Fatalf("registered type = %T, want *GenericOIDCAccessConnector", got)
	}
}

// TestStructurallyAbsentCapabilities_ReturnErrCapabilityNotSupported pins
// the sentinel contract: the three provisioning verbs return an error that
// (a) matches the package-local ErrNotImplemented for backward compat, and
// (b) unwraps to access.ErrCapabilityNotSupported so the worker's finalize()
// routes the job to status=skipped (not status=failed). This is the same
// dual-sentinel pattern used by hibp, bitsight, virustotal, and wazuh.
func TestStructurallyAbsentCapabilities_ReturnErrCapabilityNotSupported(t *testing.T) {
	c := New()

	// Package-local sentinel compat.
	if err := c.ProvisionAccess(context.Background(), nil, nil, access.AccessGrant{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("ProvisionAccess: want ErrNotImplemented, got %v", err)
	}
	if err := c.RevokeAccess(context.Background(), nil, nil, access.AccessGrant{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("RevokeAccess: want ErrNotImplemented, got %v", err)
	}
	if _, err := c.ListEntitlements(context.Background(), nil, nil, "user"); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("ListEntitlements: want ErrNotImplemented, got %v", err)
	}

	// Canonical platform sentinel compat.
	if err := c.ProvisionAccess(context.Background(), nil, nil, access.AccessGrant{}); !errors.Is(err, access.ErrCapabilityNotSupported) {
		t.Fatalf("ProvisionAccess: want ErrCapabilityNotSupported, got %v", err)
	}
	if err := c.RevokeAccess(context.Background(), nil, nil, access.AccessGrant{}); !errors.Is(err, access.ErrCapabilityNotSupported) {
		t.Fatalf("RevokeAccess: want ErrCapabilityNotSupported, got %v", err)
	}
	if _, err := c.ListEntitlements(context.Background(), nil, nil, "user"); !errors.Is(err, access.ErrCapabilityNotSupported) {
		t.Fatalf("ListEntitlements: want ErrCapabilityNotSupported, got %v", err)
	}
}

func TestSyncAndCount_AreNoOps(t *testing.T) {
	c := New()
	n, err := c.CountIdentities(context.Background(), nil, nil)
	if err != nil || n != 0 {
		t.Fatalf("CountIdentities = %d, %v", n, err)
	}
	called := false
	if err := c.SyncIdentities(context.Background(), nil, nil, "", func(_ []*access.Identity, _ string) error {
		called = true
		return nil
	}); err != nil {
		t.Fatalf("SyncIdentities: %v", err)
	}
	if called {
		t.Fatal("SyncIdentities should not invoke handler for OIDC")
	}
}

func discoveryServer(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
		}
		_, _ = w.Write([]byte(body))
	}))
	return server
}

func TestGetSSOMetadata_ParsesDiscovery(t *testing.T) {
	server := discoveryServer(t, `{
        "issuer": "ISSUER",
        "authorization_endpoint": "ISSUER/authorize",
        "token_endpoint": "ISSUER/oauth/token",
        "end_session_endpoint": "ISSUER/logout"
    }`, http.StatusOK)
	t.Cleanup(server.Close)

	cfg := validConfig(server.URL)
	// Substitute ISSUER placeholder so the discovery doc points at the test server.
	c := New()
	c.httpClient = func() httpDoer { return server.Client() }

	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := `{
            "issuer": "` + server.URL + `",
            "authorization_endpoint": "` + server.URL + `/authorize",
            "token_endpoint": "` + server.URL + `/oauth/token",
            "end_session_endpoint": "` + server.URL + `/logout"
        }`
		_, _ = w.Write([]byte(body))
		_ = r
	})

	md, err := c.GetSSOMetadata(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if md.Protocol != "oidc" {
		t.Fatalf("Protocol = %q", md.Protocol)
	}
	if md.EntityID != server.URL {
		t.Fatalf("EntityID = %q", md.EntityID)
	}
	if !strings.HasSuffix(md.MetadataURL, "/.well-known/openid-configuration") {
		t.Fatalf("MetadataURL = %q", md.MetadataURL)
	}
	if md.SSOLoginURL != server.URL+"/authorize" {
		t.Fatalf("SSOLoginURL = %q", md.SSOLoginURL)
	}
	if md.SSOLogoutURL != server.URL+"/logout" {
		t.Fatalf("SSOLogoutURL = %q", md.SSOLogoutURL)
	}
}

func TestConnect_ReturnsErrorOnMalformedDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer": "x"}`)) // missing required fields
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClient = func() httpDoer { return server.Client() }

	if err := c.Connect(context.Background(), validConfig(server.URL), validSecrets()); err == nil {
		t.Fatal("Connect expected error on malformed discovery doc")
	}
}

func TestConnect_ReturnsErrorOnNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClient = func() httpDoer { return server.Client() }

	if err := c.Connect(context.Background(), validConfig(server.URL), validSecrets()); err == nil {
		t.Fatal("Connect expected error on 500")
	}
}

func TestVerifyPermissions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
            "issuer": "x",
            "authorization_endpoint": "x/authorize",
            "token_endpoint": "x/token"
        }`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClient = func() httpDoer { return server.Client() }

	missing, err := c.VerifyPermissions(context.Background(), validConfig(server.URL), validSecrets(), []string{"sso_federation", "sync_identity"})
	if err != nil {
		t.Fatalf("VerifyPermissions: %v", err)
	}
	if len(missing) != 1 || !strings.HasPrefix(missing[0], "sync_identity") {
		t.Fatalf("missing = %v", missing)
	}
}

func TestGetCredentialsMetadata(t *testing.T) {
	c := New()
	md, err := c.GetCredentialsMetadata(context.Background(), nil, validSecrets())
	if err != nil {
		t.Fatalf("GetCredentialsMetadata: %v", err)
	}
	if md["provider"] != ProviderName {
		t.Fatalf("provider = %v", md["provider"])
	}
	if md["client_id"] != "rp-id" {
		t.Fatalf("client_id = %v", md["client_id"])
	}
}
