package auth0

import (
	"errors"
	"fmt"
	"strings"
)

// ProviderName is the registry key for the Auth0 connector.
const ProviderName = "auth0"

// Config is the operator-visible configuration for an Auth0 connector
// instance. The Domain is the customer's Auth0 tenant domain — for example
// "uney.us.auth0.com" or "uney.eu.auth0.com".
type Config struct {
	// Domain is the Auth0 tenant domain. Must contain ".auth0.com".
	Domain string `json:"domain"`
}

// Secrets is the secret material stored encrypted in
// access_connectors.credentials. Auth0 uses Machine-to-Machine application
// credentials (Client ID + Client Secret) authorised against the Management
// API.
type Secrets struct {
	// ClientID is the M2M application client_id.
	ClientID string `json:"client_id"`
	// ClientSecret is the M2M application client_secret.
	ClientSecret string `json:"client_secret"`
}

// DecodeConfig pulls a typed Config out of the operator-supplied payload.
func DecodeConfig(raw map[string]interface{}) (Config, error) {
	var cfg Config
	if raw == nil {
		return cfg, errors.New("auth0: config is nil")
	}
	if v, ok := raw["domain"].(string); ok {
		cfg.Domain = v
	}
	return cfg, nil
}

// DecodeSecrets pulls a typed Secrets out of the decrypted secrets payload.
func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	var s Secrets
	if raw == nil {
		return s, errors.New("auth0: secrets is nil")
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
	if c.Domain == "" {
		return errors.New("auth0: domain is required")
	}
	domain := c.normalised()
	if !strings.Contains(domain, ".auth0.com") {
		return fmt.Errorf("auth0: domain %q must contain .auth0.com", c.Domain)
	}
	return nil
}

// validate is the pure-local check for Secrets.
func (s Secrets) validate() error {
	if s.ClientID == "" {
		return errors.New("auth0: client_id is required")
	}
	if s.ClientSecret == "" {
		return errors.New("auth0: client_secret is required")
	}
	return nil
}

// normalised returns the domain stripped of scheme / trailing slash and
// lowercased, suitable for URL composition.
func (c Config) normalised() string {
	d := strings.ToLower(c.Domain)
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimSuffix(d, "/")
	return d
}
