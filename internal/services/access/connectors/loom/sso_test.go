package loom

import (
	"context"
	"testing"
)

func TestLoomGetSSOMetadata_NilWithoutURL(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got != nil {
		t.Fatalf("got = %+v; want nil", got)
	}
}

func TestLoomGetSSOMetadata_WithMetadataURL(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{
		"sso_metadata_url": "https://www.loom.com/sso/saml/acme/metadata",
		"sso_entity_id":    "https://www.loom.com/sso/saml/acme",
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
