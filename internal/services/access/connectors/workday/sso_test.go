package workday

import (
	"context"
	"testing"
)

func TestWorkdayGetSSOMetadata_ErrorsOnNilConfig(t *testing.T) {
	c := New()
	if _, err := c.GetSSOMetadata(context.Background(), nil, nil); err == nil {
		t.Fatal("GetSSOMetadata(nil) err = nil; want non-nil")
	}
}

func TestWorkdayGetSSOMetadata_DerivesURLFromHostAndTenant(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{
		"host":   "wd5-impl-services1.workday.com",
		"tenant": "acme1",
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
	if got.MetadataURL != "https://wd5-impl-services1.workday.com/acme1/saml2/metadata" {
		t.Errorf("MetadataURL = %q", got.MetadataURL)
	}
	if got.EntityID != "https://wd5-impl-services1.workday.com/acme1" {
		t.Errorf("EntityID = %q", got.EntityID)
	}
}
