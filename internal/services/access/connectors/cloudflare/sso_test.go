package cloudflare

import (
	"context"
	"strings"
	"testing"
)

func TestGetSSOMetadata_NilWithoutTeamDomain(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{"account_id": "abc"}, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got != nil {
		t.Fatalf("got = %+v; want nil", got)
	}
}

func TestGetSSOMetadata_WithTeamDomain(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{"account_id": "abc", "team_domain": "acme"}, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got == nil {
		t.Fatal("got = nil")
	}
	if got.Protocol != "saml" {
		t.Errorf("Protocol = %q; want saml", got.Protocol)
	}
	if !strings.Contains(got.MetadataURL, "acme.cloudflareaccess.com") {
		t.Errorf("MetadataURL = %q", got.MetadataURL)
	}
	if got.EntityID != "https://acme.cloudflareaccess.com" {
		t.Errorf("EntityID = %q", got.EntityID)
	}
}

func TestGetSSOMetadata_RejectsNonDNSLabelTeamDomain(t *testing.T) {
	// Inputs that would otherwise inject extra hosts/paths into the
	// constructed cloudflareaccess.com URL must be rejected as
	// non-DNS-label team_domain values.
	cases := []string{
		"evil.com/",
		"acme.evil.com",
		"acme/",
		"acme corp",
		"-acme",
		"acme-",
		"acme:80",
		"acme?x=1",
		"acme#frag",
		"acme@evil",
	}
	c := New()
	for _, v := range cases {
		_, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{"account_id": "abc", "team_domain": v}, nil)
		if err == nil {
			t.Errorf("GetSSOMetadata(team_domain=%q) err = nil; want non-nil", v)
			continue
		}
		if !strings.Contains(err.Error(), "DNS label") {
			t.Errorf("GetSSOMetadata(team_domain=%q) err = %v; want DNS-label rejection", v, err)
		}
	}
}

func TestConfig_ValidateRejectsNonDNSLabelTeamDomain(t *testing.T) {
	cfg := Config{AccountID: "abc", TeamDomain: "evil.com/"}
	if err := cfg.validate(); err == nil {
		t.Fatal("validate() err = nil; want non-nil for malformed team_domain")
	}
}
