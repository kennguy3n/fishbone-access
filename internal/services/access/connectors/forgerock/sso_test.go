package forgerock

import (
	"context"
	"strings"
	"testing"
)

func TestGetSSOMetadata_NilWithoutEndpoint(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got != nil {
		t.Fatalf("got = %+v; want nil", got)
	}
}

func TestGetSSOMetadata_WithEndpoint(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{
		"endpoint": "https://idm.corp.example/",
	}, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got == nil {
		t.Fatal("got = nil")
	}
	if got.Protocol != "oidc" {
		t.Errorf("Protocol = %q", got.Protocol)
	}
	if !strings.HasSuffix(got.MetadataURL, "/.well-known/openid-configuration") {
		t.Errorf("MetadataURL = %q", got.MetadataURL)
	}
	if got.EntityID != "https://idm.corp.example" {
		t.Errorf("EntityID = %q", got.EntityID)
	}
}
