package generic_saml

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// genericSAMLMetadataServer returns an httptest server that publishes a
// well-formed SAML 2.0 metadata XML document at any path so the
// connector's GET against cfg.MetadataURL succeeds.
func genericSAMLMetadataServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write([]byte(sampleMetadata))
	}))
	return srv
}

// TestGenericSAMLConnectorFlow_LifecycleSentinel locks the documented
// SSO-only contract for the generic SAML connector: Validate is
// pure-local, Connect probes the metadata XML, SyncIdentities is a
// no-op, and the three provisioning verbs return both ErrNotImplemented
// (package-local compat) and access.ErrCapabilityNotSupported (canonical
// platform sentinel) because SAML 2.0 has no user-management surface.
// The worker finalize() treats this as a structural skip.
func TestGenericSAMLConnectorFlow_LifecycleSentinel(t *testing.T) {
	srv := genericSAMLMetadataServer(t)
	t.Cleanup(srv.Close)

	c := New()
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := validConfig(srv.URL + "/metadata")

	if err := c.Validate(context.Background(), cfg, nil); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := c.Connect(context.Background(), cfg, nil); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	called := false
	if err := c.SyncIdentities(context.Background(), cfg, nil, "", func(_ []*access.Identity, _ string) error {
		called = true
		return nil
	}); err != nil {
		t.Fatalf("SyncIdentities: %v", err)
	}
	if called {
		t.Fatal("SyncIdentities must not invoke the handler for an SAML-only connector")
	}

	grant := access.AccessGrant{UserExternalID: "alice@example.com"}
	if err := c.ProvisionAccess(context.Background(), cfg, nil, grant); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("ProvisionAccess err = %v; want ErrNotImplemented sentinel", err)
	}
	if err := c.RevokeAccess(context.Background(), cfg, nil, grant); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("RevokeAccess err = %v; want ErrNotImplemented sentinel", err)
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, nil, "alice@example.com")
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("ListEntitlements err = %v; want ErrNotImplemented sentinel", err)
	}
	if len(ents) != 0 {
		t.Fatalf("ListEntitlements returned %d entitlements; want 0 alongside the sentinel", len(ents))
	}

	// The sentinel must also unwrap to the canonical platform sentinel.
	if err := c.ProvisionAccess(context.Background(), cfg, nil, grant); !errors.Is(err, access.ErrCapabilityNotSupported) {
		t.Fatalf("ProvisionAccess err = %v; want access.ErrCapabilityNotSupported", err)
	}

	md, err := c.GetSSOMetadata(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if md == nil || md.Protocol != "saml" {
		t.Fatalf("GetSSOMetadata = %#v; want non-nil SAML metadata", md)
	}
}

// TestGenericSAMLConnectorFlow_ConnectFailureForbidden asserts the 403
// path on the metadata endpoint surfaces upstream so callers can
// distinguish hard auth failures from documented no-ops.
func TestGenericSAMLConnectorFlow_ConnectFailureForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.Connect(context.Background(), validConfig(srv.URL+"/metadata"), nil)
	if err == nil {
		t.Fatal("Connect expected error on 403")
	}
}
