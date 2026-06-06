package gitlab

import (
	"context"
	"strings"
	"testing"
)

func TestGitLabGetSSOMetadata_ErrorsOnNilConfig(t *testing.T) {
	c := New()
	if _, err := c.GetSSOMetadata(context.Background(), nil, nil); err == nil {
		t.Fatal("GetSSOMetadata(nil) err = nil; want non-nil")
	}
}

func TestGitLabGetSSOMetadata_UsesDefaultBaseURL(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{
		"group_id": "acme",
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
	if !strings.HasPrefix(got.MetadataURL, "https://gitlab.com/groups/acme/-/saml/metadata") {
		t.Errorf("MetadataURL = %q", got.MetadataURL)
	}
	if got.EntityID != "https://gitlab.com/groups/acme" {
		t.Errorf("EntityID = %q", got.EntityID)
	}
}

func TestGitLabGetSSOMetadata_SelfHostedBaseURL(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{
		"group_id": "platform",
		"base_url": "https://gitlab.acme.internal/",
	}, validSecrets())
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got.MetadataURL != "https://gitlab.acme.internal/groups/platform/-/saml/metadata" {
		t.Errorf("MetadataURL = %q", got.MetadataURL)
	}
	if got.EntityID != "https://gitlab.acme.internal/groups/platform" {
		t.Errorf("EntityID = %q", got.EntityID)
	}
}
