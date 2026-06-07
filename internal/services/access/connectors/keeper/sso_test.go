package keeper

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

// TestGetSSOMetadata_WithMetadataURL pins the connector to the shared
// `sso_*` config convention (access.SSOMetadataFromConfig). A regression
// that reverts to bespoke `saml_metadata_url` keys would make this fail:
// the standard `sso_metadata_url` an operator supplies must be honored.
func TestGetSSOMetadata_WithMetadataURL(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{
		"sso_metadata_url": "https://keepersecurity.com/sso/saml/abc/metadata",
		"sso_entity_id":    "https://keepersecurity.com/abc",
		"sso_login_url":    "https://keepersecurity.com/sso/saml/abc/login",
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
	if got.MetadataURL != "https://keepersecurity.com/sso/saml/abc/metadata" {
		t.Errorf("MetadataURL = %q", got.MetadataURL)
	}
	if got.EntityID != "https://keepersecurity.com/abc" {
		t.Errorf("EntityID = %q", got.EntityID)
	}
	if got.SSOLoginURL != "https://keepersecurity.com/sso/saml/abc/login" {
		t.Errorf("SSOLoginURL = %q", got.SSOLoginURL)
	}
}
