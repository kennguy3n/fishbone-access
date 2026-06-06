package azure

import (
	"context"
	"strings"
	"testing"
)

func TestAzureGetSSOMetadata_DefaultsToOIDC(t *testing.T) {
	c := New()
	cfg := map[string]interface{}{
		"tenant_id":       "11111111-2222-3333-4444-555555555555",
		"subscription_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
	}
	m, err := c.GetSSOMetadata(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if m == nil {
		t.Fatal("metadata is nil")
	}
	if m.Protocol != "oidc" {
		t.Errorf("Protocol = %q, want oidc", m.Protocol)
	}
	if !strings.Contains(m.MetadataURL, "/.well-known/openid-configuration") {
		t.Errorf("MetadataURL = %q", m.MetadataURL)
	}
	if !strings.Contains(m.MetadataURL, "11111111-2222-3333-4444-555555555555") {
		t.Errorf("MetadataURL does not contain tenant: %q", m.MetadataURL)
	}
}

func TestAzureGetSSOMetadata_SAML(t *testing.T) {
	c := New()
	cfg := map[string]interface{}{
		"tenant_id":       "11111111-2222-3333-4444-555555555555",
		"subscription_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"sso_protocol":    "saml",
	}
	m, err := c.GetSSOMetadata(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if m == nil {
		t.Fatal("metadata is nil")
	}
	if m.Protocol != "saml" {
		t.Errorf("Protocol = %q", m.Protocol)
	}
	if !strings.Contains(m.MetadataURL, "federationmetadata.xml") {
		t.Errorf("MetadataURL = %q", m.MetadataURL)
	}
	if !strings.Contains(m.SSOLogoutURL, "saml2/logout") {
		t.Errorf("SSOLogoutURL = %q", m.SSOLogoutURL)
	}
}

func TestAzureGetSSOMetadata_RejectsUnknownProtocol(t *testing.T) {
	c := New()
	cfg := map[string]interface{}{
		"tenant_id":       "11111111-2222-3333-4444-555555555555",
		"subscription_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"sso_protocol":    "ws-fed",
	}
	if _, err := c.GetSSOMetadata(context.Background(), cfg, nil); err == nil {
		t.Fatal("err = nil, want unsupported sso_protocol")
	}
}

// SSO federation metadata derives from the tenant id alone, so it must
// succeed even when subscription_id has not been populated yet.
func TestAzureGetSSOMetadata_WorksWithoutSubscriptionID(t *testing.T) {
	c := New()
	cfg := map[string]interface{}{
		"tenant_id": "11111111-2222-3333-4444-555555555555",
	}
	m, err := c.GetSSOMetadata(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if m == nil || m.Protocol != "oidc" ||
		!strings.Contains(m.MetadataURL, "11111111-2222-3333-4444-555555555555") {
		t.Fatalf("metadata = %+v", m)
	}
	// tenant_id remains required.
	if _, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{}, nil); err == nil {
		t.Fatal("err = nil, want tenant_id required")
	}
}

// GetSSOMetadata must apply the same tenant-format validation as every
// other method, so a setup/validation flow can't accept a malformed
// tenant_id here that Connect/SyncIdentities would later reject.
func TestAzureGetSSOMetadata_RejectsMalformedTenant(t *testing.T) {
	c := New()
	for _, tenant := range []string{"../evil", "tenant id", "a/b", "tenant\\x"} {
		cfg := map[string]interface{}{"tenant_id": tenant}
		if _, err := c.GetSSOMetadata(context.Background(), cfg, nil); err == nil {
			t.Errorf("tenant_id %q: err = nil, want rejection", tenant)
		}
	}
}
