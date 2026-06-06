package access

import "testing"

// TestSSOMetadataFromConfig_NilConfig verifies that a nil config map
// downgrades cleanly to a nil *SSOMetadata so connectors with
// optional SSO federation skip the iam-core wire-in.
func TestSSOMetadataFromConfig_NilConfig(t *testing.T) {
	if got := SSOMetadataFromConfig(nil, "saml"); got != nil {
		t.Errorf("SSOMetadataFromConfig(nil) = %+v; want nil", got)
	}
}

// TestSSOMetadataFromConfig_MissingMetadataURL verifies that a
// config without the sso_metadata_url key returns nil so the
// connector treats SSO as un-configured (docs/architecture.md §13: SSO is
// opt-in per connector).
func TestSSOMetadataFromConfig_MissingMetadataURL(t *testing.T) {
	cfg := map[string]interface{}{
		"sso_entity_id": "https://example.com/sso",
	}
	if got := SSOMetadataFromConfig(cfg, "saml"); got != nil {
		t.Errorf("SSOMetadataFromConfig(missing url) = %+v; want nil", got)
	}
}

// TestSSOMetadataFromConfig_BlankMetadataURL verifies whitespace-
// only metadata URLs are treated the same as missing (the helper
// trims before checking emptiness).
func TestSSOMetadataFromConfig_BlankMetadataURL(t *testing.T) {
	for _, blank := range []string{"", "   ", "\t\n"} {
		cfg := map[string]interface{}{"sso_metadata_url": blank}
		if got := SSOMetadataFromConfig(cfg, "saml"); got != nil {
			t.Errorf("SSOMetadataFromConfig(%q) = %+v; want nil", blank, got)
		}
	}
}

// TestSSOMetadataFromConfig_ValidConfig_DefaultProtocol verifies
// that with all keys set and no sso_protocol override, the
// supplied defaultProtocol is preserved verbatim.
func TestSSOMetadataFromConfig_ValidConfig_DefaultProtocol(t *testing.T) {
	cfg := map[string]interface{}{
		"sso_metadata_url": "https://idp.example.com/metadata.xml",
		"sso_entity_id":    "urn:example:idp",
		"sso_login_url":    "https://idp.example.com/sso",
		"sso_logout_url":   "https://idp.example.com/slo",
	}
	got := SSOMetadataFromConfig(cfg, "saml")
	if got == nil {
		t.Fatal("SSOMetadataFromConfig = nil; want populated metadata")
	}
	if got.Protocol != "saml" {
		t.Errorf("Protocol = %q; want saml (default)", got.Protocol)
	}
	if got.MetadataURL != "https://idp.example.com/metadata.xml" {
		t.Errorf("MetadataURL = %q", got.MetadataURL)
	}
	if got.EntityID != "urn:example:idp" {
		t.Errorf("EntityID = %q", got.EntityID)
	}
	if got.SSOLoginURL != "https://idp.example.com/sso" {
		t.Errorf("SSOLoginURL = %q", got.SSOLoginURL)
	}
	if got.SSOLogoutURL != "https://idp.example.com/slo" {
		t.Errorf("SSOLogoutURL = %q", got.SSOLogoutURL)
	}
}

// TestSSOMetadataFromConfig_ProtocolOverride verifies that the
// sso_protocol key takes precedence over the defaultProtocol so
// SAML-default connectors can be flipped to OIDC by the operator.
func TestSSOMetadataFromConfig_ProtocolOverride(t *testing.T) {
	cfg := map[string]interface{}{
		"sso_metadata_url": "https://idp.example.com/.well-known/openid-configuration",
		"sso_protocol":     "oidc",
	}
	got := SSOMetadataFromConfig(cfg, "saml")
	if got == nil {
		t.Fatal("SSOMetadataFromConfig = nil; want populated metadata")
	}
	if got.Protocol != "oidc" {
		t.Errorf("Protocol = %q; want oidc (override)", got.Protocol)
	}
}

// TestSSOMetadataFromConfig_ProtocolOverride_BlankFallsBack
// verifies that a blank sso_protocol value falls back to the
// supplied default (so operators cannot accidentally null it out).
func TestSSOMetadataFromConfig_ProtocolOverride_BlankFallsBack(t *testing.T) {
	cfg := map[string]interface{}{
		"sso_metadata_url": "https://idp.example.com/metadata.xml",
		"sso_protocol":     "   ",
	}
	got := SSOMetadataFromConfig(cfg, "saml")
	if got == nil {
		t.Fatal("SSOMetadataFromConfig = nil; want populated metadata")
	}
	if got.Protocol != "saml" {
		t.Errorf("Protocol = %q; want saml (default after blank override)", got.Protocol)
	}
}

// TestSSOMetadataFromConfig_NonStringValuesIgnored verifies the
// stringFromMap helper safely ignores non-string entries (an
// operator typo that produces a numeric/bool value MUST NOT crash
// the connector).
func TestSSOMetadataFromConfig_NonStringValuesIgnored(t *testing.T) {
	cfg := map[string]interface{}{
		"sso_metadata_url": "https://idp.example.com/metadata.xml",
		"sso_entity_id":    42,
		"sso_login_url":    true,
	}
	got := SSOMetadataFromConfig(cfg, "saml")
	if got == nil {
		t.Fatal("SSOMetadataFromConfig = nil; want populated metadata")
	}
	if got.EntityID != "" {
		t.Errorf("EntityID = %q; want empty (non-string ignored)", got.EntityID)
	}
	if got.SSOLoginURL != "" {
		t.Errorf("SSOLoginURL = %q; want empty (non-string ignored)", got.SSOLoginURL)
	}
}

// TestStringFromMap_NilMap verifies the private helper degrades
// gracefully when the caller hands it nil — connectors call this
// in their Validate path before sniffing the config.
func TestStringFromMap_NilMap(t *testing.T) {
	if got := stringFromMap(nil, "any"); got != "" {
		t.Errorf("stringFromMap(nil) = %q; want empty", got)
	}
}
