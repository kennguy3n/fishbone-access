package bamboohr

import (
	"context"
	"testing"
)

func TestBambooHRGetSSOMetadata_ErrorsOnNilConfig(t *testing.T) {
	c := New()
	if _, err := c.GetSSOMetadata(context.Background(), nil, nil); err == nil {
		t.Fatal("GetSSOMetadata(nil) err = nil; want non-nil")
	}
}

// TestBambooHRGetSSOMetadata_WorksWithoutSecrets guards the contract that
// SSO metadata discovery only needs config (the subdomain), so it keeps
// working when API credentials are absent, rotated, or expired.
func TestBambooHRGetSSOMetadata_WorksWithoutSecrets(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{
		"subdomain": "acme",
	}, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata without secrets: %v", err)
	}
	if got == nil || got.MetadataURL != "https://acme.bamboohr.com/saml/metadata" {
		t.Fatalf("got = %+v", got)
	}
}

// TestBambooHRValidate_RejectsMalformedSubdomain ensures a subdomain that
// is not a clean DNS label cannot be interpolated into a hostname (which
// could otherwise point baseURL/ssoBaseURL at an unintended host).
func TestBambooHRValidate_RejectsMalformedSubdomain(t *testing.T) {
	c := New()
	for _, bad := range []string{"evil.com#", "a/b", "foo.bar", "has space", "-leading", "trailing-"} {
		err := c.Validate(context.Background(), map[string]interface{}{"subdomain": bad}, validSecrets())
		if err == nil {
			t.Errorf("subdomain %q accepted; want rejected", bad)
		}
	}
	if err := c.Validate(context.Background(), map[string]interface{}{"subdomain": "acme-corp1"}, validSecrets()); err != nil {
		t.Errorf("valid subdomain rejected: %v", err)
	}
}

func TestBambooHRGetSSOMetadata_DerivesURLFromSubdomain(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{
		"subdomain": "acme",
	}, validSecrets())
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got == nil {
		t.Fatal("got = nil")
	}
	if got.Protocol != "saml" {
		t.Errorf("Protocol = %q; want saml", got.Protocol)
	}
	if got.MetadataURL != "https://acme.bamboohr.com/saml/metadata" {
		t.Errorf("MetadataURL = %q", got.MetadataURL)
	}
	if got.EntityID != "https://acme.bamboohr.com" {
		t.Errorf("EntityID = %q", got.EntityID)
	}
}
