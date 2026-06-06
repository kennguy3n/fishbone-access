package generic_oidc

import (
	"errors"
	"net/url"
	"strings"
)

// ProviderName is the registry key for the Generic OIDC connector.
const ProviderName = "generic_oidc"

// Config is the operator-visible configuration for a Generic OIDC connector
// instance. OIDC connectors federate SSO only — they do not sync identities
// or push grants.
type Config struct {
	// IssuerURL is the OIDC issuer (e.g. "https://accounts.example.com").
	// The connector probes <IssuerURL>/.well-known/openid-configuration.
	IssuerURL string `json:"issuer_url"`
	// DisplayName is the operator-visible label for the connector instance.
	DisplayName string `json:"display_name"`
}

// Secrets holds the relying-party credentials issued by the IdP.
type Secrets struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// DecodeConfig pulls a typed Config out of the operator-supplied payload.
func DecodeConfig(raw map[string]interface{}) (Config, error) {
	var cfg Config
	if raw == nil {
		return cfg, errors.New("generic_oidc: config is nil")
	}
	if v, ok := raw["issuer_url"].(string); ok {
		cfg.IssuerURL = v
	}
	if v, ok := raw["display_name"].(string); ok {
		cfg.DisplayName = v
	}
	return cfg, nil
}

// DecodeSecrets pulls a typed Secrets out of the decrypted secrets payload.
func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	var s Secrets
	if raw == nil {
		return s, errors.New("generic_oidc: secrets is nil")
	}
	if v, ok := raw["client_id"].(string); ok {
		s.ClientID = v
	}
	if v, ok := raw["client_secret"].(string); ok {
		s.ClientSecret = v
	}
	return s, nil
}

// validate is the pure-local check for Config.
func (c Config) validate() error {
	if c.IssuerURL == "" {
		return errors.New("generic_oidc: issuer_url is required")
	}
	u, err := url.Parse(c.IssuerURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("generic_oidc: issuer_url must be an absolute URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return errors.New("generic_oidc: issuer_url must use http or https")
	}
	if c.DisplayName == "" {
		return errors.New("generic_oidc: display_name is required")
	}
	return nil
}

// validate is the pure-local check for Secrets.
func (s Secrets) validate() error {
	if s.ClientID == "" {
		return errors.New("generic_oidc: client_id is required")
	}
	if s.ClientSecret == "" {
		return errors.New("generic_oidc: client_secret is required")
	}
	return nil
}

// normalisedIssuer trims any trailing slash so we can compose well-known URLs.
func (c Config) normalisedIssuer() string {
	return strings.TrimRight(c.IssuerURL, "/")
}
