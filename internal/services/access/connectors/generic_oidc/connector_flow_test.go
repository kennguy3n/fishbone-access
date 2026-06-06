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

// genericOIDCDiscoveryServer returns an httptest server that publishes a
// well-formed OpenID Connect discovery document at the canonical path.
// The issuer field is rewritten to the server URL so consumers can
// dial straight back through the same loopback connection.
func genericOIDCDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{
            "issuer": "` + r.Host + `",
            "authorization_endpoint": "https://` + r.Host + `/authorize",
            "token_endpoint": "https://` + r.Host + `/oauth/token",
            "end_session_endpoint": "https://` + r.Host + `/logout"
        }`))
	}))
	return srv
}

// TestGenericOIDCConnectorFlow_LifecycleSentinel locks the documented
// SSO-only contract for the generic OIDC connector: Validate is
// pure-local, Connect probes the discovery endpoint, SyncIdentities is a
// no-op, and the three provisioning verbs return both ErrNotImplemented
// (package-local compat) and access.ErrCapabilityNotSupported (canonical
// platform sentinel) because OIDC Core 1.0 has no user-management
// surface. The worker finalize() treats this as a structural skip.
func TestGenericOIDCConnectorFlow_LifecycleSentinel(t *testing.T) {
	srv := genericOIDCDiscoveryServer(t)
	t.Cleanup(srv.Close)

	c := New()
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := validConfig(srv.URL)
	secrets := validSecrets()

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := c.Connect(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	called := false
	if err := c.SyncIdentities(context.Background(), cfg, secrets, "", func(_ []*access.Identity, _ string) error {
		called = true
		return nil
	}); err != nil {
		t.Fatalf("SyncIdentities: %v", err)
	}
	if called {
		t.Fatal("SyncIdentities must not invoke the handler for an SSO-only connector")
	}

	grant := access.AccessGrant{UserExternalID: "alice@example.com"}
	if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("ProvisionAccess err = %v; want ErrNotImplemented sentinel", err)
	}
	if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("RevokeAccess err = %v; want ErrNotImplemented sentinel", err)
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, "alice@example.com")
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("ListEntitlements err = %v; want ErrNotImplemented sentinel", err)
	}
	if len(ents) != 0 {
		t.Fatalf("ListEntitlements returned %d entitlements; want 0 alongside the sentinel", len(ents))
	}

	// The sentinel must also unwrap to the canonical platform sentinel.
	if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); !errors.Is(err, access.ErrCapabilityNotSupported) {
		t.Fatalf("ProvisionAccess err = %v; want access.ErrCapabilityNotSupported", err)
	}

	md, err := c.GetSSOMetadata(context.Background(), cfg, secrets)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if md == nil || md.Protocol != "oidc" {
		t.Fatalf("GetSSOMetadata = %#v; want non-nil OIDC metadata", md)
	}
	if !strings.HasSuffix(md.MetadataURL, "/.well-known/openid-configuration") {
		t.Fatalf("MetadataURL = %q", md.MetadataURL)
	}
}

// TestGenericOIDCConnectorFlow_ConnectFailureForbidden asserts the 403
// path on the discovery endpoint surfaces upstream so callers can
// distinguish hard auth failures from documented no-ops.
func TestGenericOIDCConnectorFlow_ConnectFailureForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.Connect(context.Background(), validConfig(srv.URL), validSecrets())
	if err == nil {
		t.Fatal("Connect expected error on 403")
	}
}
