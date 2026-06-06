package salesforce

import (
	"context"
	"strings"
	"testing"
)

func TestSalesforceGetSSOMetadata_ErrorsOnNilConfig(t *testing.T) {
	c := New()
	if _, err := c.GetSSOMetadata(context.Background(), nil, nil); err == nil {
		t.Fatal("GetSSOMetadata(nil) err = nil; want non-nil")
	}
}

func TestSalesforceGetSSOMetadata_DerivesURLFromInstanceURL(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{
		"instance_url": "https://acme.my.salesforce.com",
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
	if got.MetadataURL != "https://acme.my.salesforce.com/identity/saml/metadata" {
		t.Errorf("MetadataURL = %q", got.MetadataURL)
	}
	if got.EntityID != "https://acme.my.salesforce.com" {
		t.Errorf("EntityID = %q", got.EntityID)
	}
}

func TestSalesforceGetSSOMetadata_TrimsTrailingSlash(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{
		"instance_url": "https://acme.my.salesforce.com/",
	}, validSecrets())
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if strings.Contains(got.MetadataURL, "//identity") {
		t.Errorf("MetadataURL contains double slash: %q", got.MetadataURL)
	}
}
