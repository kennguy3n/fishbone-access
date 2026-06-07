package okta

import (
	"errors"
	"fmt"
	"strings"
)

// ProviderName is the registry key for the Okta connector.
const ProviderName = "okta"

// Config is the operator-visible configuration for an Okta connector
// instance.
type Config struct {
	// OktaDomain is the customer's Okta domain. Must end in .okta.com or
	// .oktapreview.com (sandbox tenants).
	OktaDomain string `json:"okta_domain"`
}

// Secrets is the secret material stored encrypted in
// access_connectors.credentials.
type Secrets struct {
	// APIToken is the SSWS-prefixed Okta API token. Some operators paste
	// the bare token, others paste with the "SSWS " prefix; the connector
	// normalises both at use-site.
	APIToken string `json:"api_token"`
}

// DecodeConfig pulls a typed Config out of the operator-supplied payload.
func DecodeConfig(raw map[string]interface{}) (Config, error) {
	var cfg Config
	if raw == nil {
		return cfg, errors.New("okta: config is nil")
	}
	if v, ok := raw["okta_domain"].(string); ok {
		cfg.OktaDomain = v
	}
	return cfg, nil
}

// DecodeSecrets pulls a typed Secrets out of the decrypted secrets payload.
func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	var s Secrets
	if raw == nil {
		return s, errors.New("okta: secrets is nil")
	}
	if v, ok := raw["api_token"].(string); ok {
		s.APIToken = v
	}
	return s, nil
}

// validate is the pure-local check for Config.
func (c Config) validate() error {
	if c.OktaDomain == "" {
		return errors.New("okta: okta_domain is required")
	}
	domain := strings.ToLower(c.OktaDomain)
	// Strip any accidental scheme.
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimSuffix(domain, "/")

	if !strings.HasSuffix(domain, ".okta.com") &&
		!strings.HasSuffix(domain, ".oktapreview.com") &&
		!strings.HasSuffix(domain, ".okta-emea.com") {
		return fmt.Errorf("okta: okta_domain %q must end in .okta.com, .oktapreview.com, or .okta-emea.com", c.OktaDomain)
	}
	return nil
}

// validate is the pure-local check for Secrets.
func (s Secrets) validate() error {
	if s.APIToken == "" {
		return errors.New("okta: api_token is required")
	}
	return nil
}

// normalisedDomain returns the okta_domain stripped of scheme / trailing slash
// and lowercased, suitable for URL composition.
func (c Config) normalisedDomain() string {
	d := strings.ToLower(c.OktaDomain)
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimSuffix(d, "/")
	return d
}
