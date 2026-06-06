package jira

import (
	"context"
	"strings"
	"testing"
)

func TestJiraGetSSOMetadata_ErrorsOnNilConfig(t *testing.T) {
	c := New()
	if _, err := c.GetSSOMetadata(context.Background(), nil, nil); err == nil {
		t.Fatal("GetSSOMetadata(nil) err = nil; want non-nil")
	}
}

func TestJiraGetSSOMetadata_DerivesURLFromSiteURL(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{
		"cloud_id": "abc-123",
		"site_url": "https://acme.atlassian.net",
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
	if got.MetadataURL != "https://acme.atlassian.net/admin/saml/metadata" {
		t.Errorf("MetadataURL = %q", got.MetadataURL)
	}
	if got.EntityID != "https://acme.atlassian.net" {
		t.Errorf("EntityID = %q", got.EntityID)
	}
}

func TestJiraGetSSOMetadata_TrimsTrailingSlash(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{
		"cloud_id": "abc-123",
		"site_url": "https://acme.atlassian.net/",
	}, validSecrets())
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if strings.Contains(got.MetadataURL, "net//admin") {
		t.Errorf("MetadataURL contains double slash: %q", got.MetadataURL)
	}
}
