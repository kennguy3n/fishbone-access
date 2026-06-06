package duo

import (
	"errors"
	"fmt"
	"strings"
)

// ProviderName is the registry key for the Duo Security connector.
const ProviderName = "duo_security"

// Config is the operator-visible configuration for a Duo Admin API connector
// instance. The APIHostname is the per-tenant host Duo provisions, e.g.
// "api-XXXXXXXX.duosecurity.com".
type Config struct {
	APIHostname string `json:"api_hostname"`
}

// Secrets holds the Duo Admin API integration credentials. Both keys are
// generated from the Duo Admin Panel under "Integrations".
type Secrets struct {
	IntegrationKey string `json:"integration_key"` // ikey
	SecretKey      string `json:"secret_key"`      // skey
}

// DecodeConfig pulls a typed Config out of the operator-supplied payload.
func DecodeConfig(raw map[string]interface{}) (Config, error) {
	var cfg Config
	if raw == nil {
		return cfg, errors.New("duo_security: config is nil")
	}
	if v, ok := raw["api_hostname"].(string); ok {
		cfg.APIHostname = v
	}
	return cfg, nil
}

// DecodeSecrets pulls a typed Secrets out of the decrypted secrets payload.
func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	var s Secrets
	if raw == nil {
		return s, errors.New("duo_security: secrets is nil")
	}
	if v, ok := raw["integration_key"].(string); ok {
		s.IntegrationKey = v
	}
	if v, ok := raw["secret_key"].(string); ok {
		s.SecretKey = v
	}
	return s, nil
}

// validate is the pure-local check for Config.
func (c Config) validate() error {
	if c.APIHostname == "" {
		return errors.New("duo_security: api_hostname is required")
	}
	host := c.normalisedHost()
	if !strings.HasSuffix(host, ".duosecurity.com") {
		return fmt.Errorf("duo_security: api_hostname %q must end in .duosecurity.com", c.APIHostname)
	}
	return nil
}

// validate is the pure-local check for Secrets.
func (s Secrets) validate() error {
	if s.IntegrationKey == "" {
		return errors.New("duo_security: integration_key is required")
	}
	if s.SecretKey == "" {
		return errors.New("duo_security: secret_key is required")
	}
	return nil
}

// normalisedHost lower-cases and strips scheme / trailing slash.
func (c Config) normalisedHost() string {
	d := strings.ToLower(c.APIHostname)
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimSuffix(d, "/")
	return d
}
