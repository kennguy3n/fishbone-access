package linode

import (
	"context"
	"testing"
)

func TestLinodeGetSSOMetadata_NilWithoutURL(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got != nil {
		t.Fatalf("got = %+v; want nil", got)
	}
}

func TestLinodeGetSSOMetadata_WithMetadataURL(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{
		"sso_metadata_url": "https://login.linode.com/saml/acme/metadata",
		"sso_entity_id":    "https://login.linode.com/saml/acme",
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
