package aws

import (
	"context"
	"testing"
)

func TestAWSGetSSOMetadata_ReturnsNilWhenUnconfigured(t *testing.T) {
	c := New()
	cfg := map[string]interface{}{
		"aws_region":     "us-east-1",
		"aws_account_id": "123456789012",
	}
	m, err := c.GetSSOMetadata(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if m != nil {
		t.Fatalf("metadata = %+v, want nil", m)
	}
}

func TestAWSGetSSOMetadata_PublishesSAMLWhenConfigured(t *testing.T) {
	c := New()
	cfg := map[string]interface{}{
		"aws_region":            "us-east-1",
		"aws_account_id":        "123456789012",
		"sso_saml_metadata_url": "https://portal.sso.us-east-1.amazonaws.com/saml/metadata/MDEyMzQ1Njc4OTAyNDU2NzAxMjM",
		"sso_saml_entity_id":    "https://portal.sso.us-east-1.amazonaws.com/saml/metadata/MDEyMzQ1Njc4OTAyNDU2NzAxMjM",
		"sso_login_url":         "https://d-1234567890.awsapps.com/start",
	}
	m, err := c.GetSSOMetadata(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if m == nil {
		t.Fatal("metadata is nil")
	}
	if m.Protocol != "saml" {
		t.Errorf("Protocol = %q", m.Protocol)
	}
	if m.MetadataURL == "" {
		t.Errorf("MetadataURL is empty")
	}
	if m.EntityID == "" {
		t.Errorf("EntityID is empty")
	}
	if m.SSOLoginURL == "" {
		t.Errorf("SSOLoginURL is empty")
	}
}
