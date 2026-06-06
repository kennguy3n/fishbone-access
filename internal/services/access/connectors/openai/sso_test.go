package openai

import (
	"context"
	"testing"
)

func TestGetSSOMetadata_NilWithoutURL(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got != nil {
		t.Fatalf("got = %+v; want nil", got)
	}
}

func TestGetSSOMetadata_WithMetadataURL(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{
		"saml_metadata_url": "https://platform.openai.com/api/saml/metadata/org-abc",
	}, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got == nil {
		t.Fatal("got = nil")
	}
	if got.Protocol != "saml" {
		t.Errorf("Protocol = %q", got.Protocol)
	}
	if got.MetadataURL != "https://platform.openai.com/api/saml/metadata/org-abc" {
		t.Errorf("MetadataURL = %q", got.MetadataURL)
	}
}
