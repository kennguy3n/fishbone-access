package gcp

import (
	"context"
	"strings"
	"testing"
)

func TestGCPGetSSOMetadata_NilWhenPoolUnset(t *testing.T) {
	c := New()
	cfg := map[string]interface{}{
		"project_id": "shieldnet-prod",
	}
	m, err := c.GetSSOMetadata(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if m != nil {
		t.Fatalf("metadata = %+v, want nil", m)
	}
}

func TestGCPGetSSOMetadata_WorkforcePoolOIDC(t *testing.T) {
	c := New()
	cfg := map[string]interface{}{
		"project_id":        "shieldnet-prod",
		"workforce_pool_id": "shieldnet-pool",
	}
	m, err := c.GetSSOMetadata(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if m == nil {
		t.Fatal("metadata is nil")
	}
	if m.Protocol != "oidc" {
		t.Errorf("Protocol = %q", m.Protocol)
	}
	if !strings.Contains(m.MetadataURL, "/locations/global/workforcePools/shieldnet-pool/.well-known/openid-configuration") {
		t.Errorf("MetadataURL = %q", m.MetadataURL)
	}
	if !strings.Contains(m.EntityID, "/workforcePools/shieldnet-pool") {
		t.Errorf("EntityID = %q", m.EntityID)
	}
}

func TestGCPGetSSOMetadata_WorkforcePoolRegional(t *testing.T) {
	c := New()
	cfg := map[string]interface{}{
		"project_id":              "shieldnet-prod",
		"workforce_pool_id":       "eu-pool",
		"workforce_pool_location": "europe-west1",
	}
	m, err := c.GetSSOMetadata(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if m == nil {
		t.Fatal("metadata is nil")
	}
	if !strings.Contains(m.MetadataURL, "/locations/europe-west1/workforcePools/eu-pool") {
		t.Errorf("MetadataURL = %q", m.MetadataURL)
	}
}
