package gorgias

import (
	"context"
	"testing"
)

func TestGorgiasGetSSOMetadata_NilWithoutURL(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got != nil {
		t.Fatalf("got = %+v; want nil", got)
	}
}

func TestGorgiasGetSSOMetadata_WithMetadataURL(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{
		"sso_metadata_url": "https://acme.gorgias.com/sso/saml/metadata",
		"sso_entity_id":    "https://acme.gorgias.com/sso/saml",
	}, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got == nil {
		t.Fatal("got = nil")
	}
	if got.Protocol != "saml" {
		t.Errorf("Protocol = %q; want saml", got.Protocol)
	}
	if got.MetadataURL == "" {
		t.Errorf("MetadataURL is empty")
	}
}
