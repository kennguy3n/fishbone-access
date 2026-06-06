package tailscale

import (
	"context"
	"testing"
)

func TestTailscaleGetSSOMetadata_NilWithoutURL(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got != nil {
		t.Fatalf("got = %+v; want nil", got)
	}
}

func TestTailscaleGetSSOMetadata_WithMetadataURL(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{
		"sso_metadata_url": "https://login.tailscale.com/.well-known/openid-configuration",
		"sso_entity_id":    "https://login.tailscale.com",
		"sso_login_url":    "https://login.tailscale.com/oauth/authorize",
	}, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got == nil {
		t.Fatal("got = nil")
	}
	if got.Protocol != "oidc" {
		t.Errorf("Protocol = %q; want oidc", got.Protocol)
	}
	if got.MetadataURL == "" {
		t.Errorf("MetadataURL is empty")
	}
	if got.EntityID == "" {
		t.Errorf("EntityID is empty")
	}
}
