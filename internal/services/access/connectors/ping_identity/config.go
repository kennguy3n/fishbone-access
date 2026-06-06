package ping_identity

import (
	"errors"
	"strings"
)

// ProviderName is the registry key for the Ping Identity (PingOne) connector.
const ProviderName = "ping_identity"

// Config is the operator-visible configuration for a PingOne connector
// instance.
type Config struct {
	// EnvironmentID is the PingOne environment UUID the worker app belongs to.
	EnvironmentID string `json:"environment_id"`
	// Region selects the regional API host: "NA", "EU", or "AP".
	Region string `json:"region"`
}

// Secrets holds the PingOne worker application credentials.
type Secrets struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// DecodeConfig pulls a typed Config out of the operator-supplied payload.
func DecodeConfig(raw map[string]interface{}) (Config, error) {
	var cfg Config
	if raw == nil {
		return cfg, errors.New("ping_identity: config is nil")
	}
	if v, ok := raw["environment_id"].(string); ok {
		cfg.EnvironmentID = v
	}
	if v, ok := raw["region"].(string); ok {
		cfg.Region = v
	}
	return cfg, nil
}

// DecodeSecrets pulls a typed Secrets out of the decrypted secrets payload.
func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	var s Secrets
	if raw == nil {
		return s, errors.New("ping_identity: secrets is nil")
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
	if strings.TrimSpace(c.EnvironmentID) == "" {
		return errors.New("ping_identity: environment_id is required")
	}
	if _, ok := regionAPIHost(c.Region); !ok {
		return errors.New(`ping_identity: region must be "NA", "EU", or "AP"`)
	}
	return nil
}

// validate is the pure-local check for Secrets.
func (s Secrets) validate() error {
	if s.ClientID == "" {
		return errors.New("ping_identity: client_id is required")
	}
	if s.ClientSecret == "" {
		return errors.New("ping_identity: client_secret is required")
	}
	return nil
}

// regionAPIHost maps a Region code to (apiHost, ok).
func regionAPIHost(region string) (string, bool) {
	switch strings.ToUpper(strings.TrimSpace(region)) {
	case "NA":
		return "api.pingone.com", true
	case "EU":
		return "api.pingone.eu", true
	case "AP":
		return "api.pingone.asia", true
	}
	return "", false
}

// regionAuthHost maps a Region code to (authHost, ok).
func regionAuthHost(region string) (string, bool) {
	switch strings.ToUpper(strings.TrimSpace(region)) {
	case "NA":
		return "auth.pingone.com", true
	case "EU":
		return "auth.pingone.eu", true
	case "AP":
		return "auth.pingone.asia", true
	}
	return "", false
}
