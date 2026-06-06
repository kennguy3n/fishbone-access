package access

import "strings"

// SSOMetadataFromConfig builds an *SSOMetadata from connector-supplied
// `configRaw` for the common case where SSO federation is an opt-in
// add-on supplied by the operator out-of-band (e.g. SAP Concur,
// LinkedIn Learning, RingCentral). Connectors call this from
// GetSSOMetadata and forward the result directly:
//
//	func (c *FooConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
//	    return access.SSOMetadataFromConfig(configRaw, "saml"), nil
//	}
//
// Recognised keys (all strings; any may be absent):
//
//   - "sso_metadata_url"  (REQUIRED; (nil) is returned when blank)
//   - "sso_entity_id"
//   - "sso_login_url"
//   - "sso_logout_url"
//   - "sso_protocol"       (optional override; otherwise `defaultProtocol`)
//
// When the metadata URL is blank the helper returns nil so callers
// gracefully downgrade — connectors do not federate SSO unless the
// operator explicitly supplies the metadata URL.
func SSOMetadataFromConfig(configRaw map[string]interface{}, defaultProtocol string) *SSOMetadata {
	if configRaw == nil {
		return nil
	}
	metaURL := strings.TrimSpace(stringFromMap(configRaw, "sso_metadata_url"))
	if metaURL == "" {
		return nil
	}
	proto := strings.TrimSpace(stringFromMap(configRaw, "sso_protocol"))
	if proto == "" {
		proto = strings.TrimSpace(defaultProtocol)
	}
	return &SSOMetadata{
		Protocol:     proto,
		MetadataURL:  metaURL,
		EntityID:     strings.TrimSpace(stringFromMap(configRaw, "sso_entity_id")),
		SSOLoginURL:  strings.TrimSpace(stringFromMap(configRaw, "sso_login_url")),
		SSOLogoutURL: strings.TrimSpace(stringFromMap(configRaw, "sso_logout_url")),
	}
}

func stringFromMap(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
