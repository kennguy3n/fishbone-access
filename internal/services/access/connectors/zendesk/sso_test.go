package zendesk

import (
	"context"
	"testing"
)

func TestZendeskGetSSOMetadata_ErrorsOnNilConfig(t *testing.T) {
	c := New()
	if _, err := c.GetSSOMetadata(context.Background(), nil, nil); err == nil {
		t.Fatal("GetSSOMetadata(nil) err = nil; want non-nil")
	}
}

func TestZendeskGetSSOMetadata_DerivesURLFromSubdomain(t *testing.T) {
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
	if got.MetadataURL != "https://acme.zendesk.com/access/saml/metadata" {
		t.Errorf("MetadataURL = %q", got.MetadataURL)
	}
	if got.EntityID != "https://acme.zendesk.com" {
		t.Errorf("EntityID = %q", got.EntityID)
	}
}
