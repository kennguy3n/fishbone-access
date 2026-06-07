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

func TestGetSSOMetadata_SharedSSOKeys(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{
		"sso_metadata_url": "https://idp.example.com/metadata",
		"sso_entity_id":    "urn:example:idp",
		"sso_login_url":    "https://idp.example.com/login",
		"sso_logout_url":   "https://idp.example.com/logout",
	}, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got == nil {
		t.Fatal("got = nil")
	}
	if got.MetadataURL != "https://idp.example.com/metadata" || got.EntityID != "urn:example:idp" {
		t.Errorf("metadata/entity = %q / %q", got.MetadataURL, got.EntityID)
	}
	if got.SSOLoginURL != "https://idp.example.com/login" || got.SSOLogoutURL != "https://idp.example.com/logout" {
		t.Errorf("login/logout = %q / %q (shared sso_* keys must be honored)", got.SSOLoginURL, got.SSOLogoutURL)
	}
}
