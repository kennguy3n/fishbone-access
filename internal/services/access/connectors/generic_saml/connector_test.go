package generic_saml

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

const sampleMetadata = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/saml">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>MIIBfakeCert==</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/saml/slo"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/saml/sso-post"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/saml/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

func validConfig(metadataURL string) map[string]interface{} {
	return map[string]interface{}{
		"metadata_url": metadataURL,
		"entity_id":    "https://sp.example.com/saml",
		"display_name": "Example IdP",
	}
}

func TestValidate_HappyPath(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig("https://idp.example.com/metadata"), nil); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_MissingFields(t *testing.T) {
	c := New()
	cases := []struct {
		name string
		cfg  map[string]interface{}
	}{
		{"missing metadata_url", map[string]interface{}{"entity_id": "x", "display_name": "y"}},
		{"missing entity_id", map[string]interface{}{"metadata_url": "https://idp.example.com/metadata", "display_name": "y"}},
		{"missing display_name", map[string]interface{}{"metadata_url": "https://idp.example.com/metadata", "entity_id": "x"}},
		{"non-url metadata", map[string]interface{}{"metadata_url": "not-a-url", "entity_id": "x", "display_name": "y"}},
		{"non-http scheme", map[string]interface{}{"metadata_url": "ftp://idp.example.com/metadata", "entity_id": "x", "display_name": "y"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := c.Validate(context.Background(), tc.cfg, nil); err == nil {
				t.Fatalf("Validate(%s) expected error", tc.name)
			}
		})
	}
}

func TestValidate_BadSigningCertPEM(t *testing.T) {
	c := New()
	cfg := validConfig("https://idp.example.com/metadata")
	secrets := map[string]interface{}{"signing_cert_pem": "not pem"}
	if err := c.Validate(context.Background(), cfg, secrets); err == nil {
		t.Fatal("Validate expected error for bad PEM")
	}
}

func TestValidate_DoesNotMakeNetworkCalls(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })

	c := New()
	if err := c.Validate(context.Background(), validConfig("https://idp.example.com/metadata"), nil); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestRegistryIntegration(t *testing.T) {
	got, err := access.GetAccessConnector(ProviderName)
	if err != nil {
		t.Fatalf("GetAccessConnector(%q): %v", ProviderName, err)
	}
	if _, ok := got.(*GenericSAMLAccessConnector); !ok {
		t.Fatalf("registered type = %T, want *GenericSAMLAccessConnector", got)
	}
}

// TestStructurallyAbsentCapabilities_ReturnErrCapabilityNotSupported pins
// the sentinel contract: the three provisioning verbs return an error that
// (a) matches the package-local ErrNotImplemented for backward compat, and
// (b) unwraps to access.ErrCapabilityNotSupported so the worker's finalize()
// routes the job to status=skipped (not status=failed).
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
		t.Fatal("SyncIdentities should not invoke handler for SAML")
	}
}

func TestGetSSOMetadata_ParsesMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write([]byte(sampleMetadata))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClient = func() httpDoer { return server.Client() }

	md, err := c.GetSSOMetadata(context.Background(), validConfig(server.URL+"/metadata"), nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if md.Protocol != "saml" {
		t.Fatalf("Protocol = %q", md.Protocol)
	}
	if md.EntityID != "https://idp.example.com/saml" {
		t.Fatalf("EntityID = %q", md.EntityID)
	}
	if md.SSOLoginURL != "https://idp.example.com/saml/sso" {
		t.Fatalf("SSOLoginURL = %q (want HTTP-Redirect chosen)", md.SSOLoginURL)
	}
	if md.SSOLogoutURL != "https://idp.example.com/saml/slo" {
		t.Fatalf("SSOLogoutURL = %q", md.SSOLogoutURL)
	}
	if len(md.SigningCertificates) != 1 || !strings.Contains(md.SigningCertificates[0], "MIIBfakeCert") {
		t.Fatalf("SigningCertificates = %v", md.SigningCertificates)
	}
}

func TestGetSSOMetadata_RejectsNonSAMLBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<root><other/></root>`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClient = func() httpDoer { return server.Client() }

	if _, err := c.GetSSOMetadata(context.Background(), validConfig(server.URL+"/metadata"), nil); err == nil {
		t.Fatal("GetSSOMetadata expected error for non-SAML body")
	}
}

func TestConnect_ReturnsErrorOnNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClient = func() httpDoer { return server.Client() }

	if err := c.Connect(context.Background(), validConfig(server.URL+"/metadata"), nil); err == nil {
		t.Fatal("Connect expected error on 500")
	}
}

func TestVerifyPermissions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(sampleMetadata))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClient = func() httpDoer { return server.Client() }

	missing, err := c.VerifyPermissions(context.Background(), validConfig(server.URL+"/metadata"), nil, []string{"sso_federation", "sync_identity"})
	if err != nil {
		t.Fatalf("VerifyPermissions: %v", err)
	}
	if len(missing) != 1 || !strings.HasPrefix(missing[0], "sync_identity") {
		t.Fatalf("missing = %v", missing)
	}
}

func TestGetCredentialsMetadata_FlagsSigningCert(t *testing.T) {
	c := New()
	md, err := c.GetCredentialsMetadata(context.Background(), nil, map[string]interface{}{
		"signing_cert_pem": "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
	})
	if err != nil {
		t.Fatalf("GetCredentialsMetadata: %v", err)
	}
	if md["provider"] != ProviderName {
		t.Fatalf("provider = %v", md["provider"])
	}
	if md["has_signing_cert"] != true {
		t.Fatalf("has_signing_cert = %v", md["has_signing_cert"])
	}

	md2, err := c.GetCredentialsMetadata(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("GetCredentialsMetadata: %v", err)
	}
	if md2["has_signing_cert"] != false {
		t.Fatalf("has_signing_cert = %v", md2["has_signing_cert"])
	}
}
