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
