package generic_saml

import (
	"errors"
	"net/url"
	"strings"
)

// ProviderName is the registry key for the Generic SAML connector.
const ProviderName = "generic_saml"

// Config is the operator-visible configuration for a Generic SAML connector
// instance. SAML connectors federate SSO only — they do not sync identities
// or push grants.
type Config struct {
	// MetadataURL is the IdP's SAML metadata XML endpoint. The connector
	// fetches and parses this URL during Connect / GetSSOMetadata.
	MetadataURL string `json:"metadata_url"`
	// EntityID is the SP entity ID this platform advertises to the IdP.
	EntityID string `json:"entity_id"`
	// DisplayName is the operator-visible label for the connector instance.
	DisplayName string `json:"display_name"`
}

// Secrets holds optional SP-side material. SAML connectors typically rely on
// the IdP's published certificates (extracted from MetadataURL); the
// SigningCertPEM here is the SP's own signing certificate, used only when
// the IdP requires signed AuthnRequests.
type Secrets struct {
	// SigningCertPEM is the SP signing certificate in PEM form. Optional.
	SigningCertPEM string `json:"signing_cert_pem"`
}

// DecodeConfig pulls a typed Config out of the operator-supplied payload.
func DecodeConfig(raw map[string]interface{}) (Config, error) {
	var cfg Config
	if raw == nil {
		return cfg, errors.New("generic_saml: config is nil")
	}
	if v, ok := raw["metadata_url"].(string); ok {
		cfg.MetadataURL = v
	}
	if v, ok := raw["entity_id"].(string); ok {
		cfg.EntityID = v
	}
	if v, ok := raw["display_name"].(string); ok {
		cfg.DisplayName = v
	}
	return cfg, nil
}

// DecodeSecrets pulls a typed Secrets out of the decrypted secrets payload.
// The whole payload is optional for SAML — operators may pass nil.
func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	var s Secrets
	if raw == nil {
		return s, nil
	}
	if v, ok := raw["signing_cert_pem"].(string); ok {
		s.SigningCertPEM = v
	}
	return s, nil
}

// validate is the pure-local check for Config.
func (c Config) validate() error {
	if c.MetadataURL == "" {
		return errors.New("generic_saml: metadata_url is required")
	}
	u, err := url.Parse(c.MetadataURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("generic_saml: metadata_url must be an absolute URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return errors.New("generic_saml: metadata_url must use http or https")
	}
	if c.EntityID == "" {
		return errors.New("generic_saml: entity_id is required")
	}
	if c.DisplayName == "" {
		return errors.New("generic_saml: display_name is required")
	}
	return nil
}

// validate is the pure-local check for Secrets. SigningCertPEM is optional;
// when present we just confirm it looks like a PEM block.
func (s Secrets) validate() error {
	if s.SigningCertPEM == "" {
		return nil
	}
	if !strings.Contains(s.SigningCertPEM, "BEGIN CERTIFICATE") {
		return errors.New("generic_saml: signing_cert_pem does not look like PEM")
	}
	return nil
}

// hasSigningCert reports whether a signing certificate is configured.
func (s Secrets) hasSigningCert() bool {
	return strings.TrimSpace(s.SigningCertPEM) != ""
}
