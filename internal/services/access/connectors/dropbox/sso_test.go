package dropbox

import (
	"context"
	"testing"
)

func TestDropboxGetSSOMetadata_ReturnsHostedMetadata(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got == nil {
		t.Fatal("got = nil")
	}
	if got.Protocol != "saml" {
		t.Errorf("Protocol = %q; want saml", got.Protocol)
	}
	if got.MetadataURL != "https://www.dropbox.com/saml_login/metadata" {
		t.Errorf("MetadataURL = %q", got.MetadataURL)
	}
	if got.EntityID != "https://www.dropbox.com" {
		t.Errorf("EntityID = %q", got.EntityID)
	}
}

func TestDropboxGetSSOMetadata_IgnoresConfigOverrides(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{
		"sso_metadata_url": "https://evil.example/metadata",
		"sso_entity_id":    "https://evil.example",
	}, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got.MetadataURL != "https://www.dropbox.com/saml_login/metadata" {
		t.Errorf("MetadataURL = %q; want hosted value", got.MetadataURL)
	}
	if got.EntityID != "https://www.dropbox.com" {
		t.Errorf("EntityID = %q; want hosted value", got.EntityID)
	}
}
