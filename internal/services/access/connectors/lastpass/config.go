package lastpass

import (
	"errors"
	"strings"
)

// ProviderName is the registry key for the LastPass connector.
const ProviderName = "lastpass"

// Config is the operator-visible configuration for a LastPass Enterprise
// connector instance.
type Config struct {
	// AccountNumber is the enterprise account number ("CID") issued by
	// LastPass.
	AccountNumber string `json:"account_number"`
}

// Secrets holds the LastPass Enterprise provisioning hash. Operators
// generate this in the LastPass admin console.
type Secrets struct {
	ProvisioningHash string `json:"provisioning_hash"`
}

// DecodeConfig pulls a typed Config out of the operator-supplied payload.
func DecodeConfig(raw map[string]interface{}) (Config, error) {
	var cfg Config
	if raw == nil {
		return cfg, errors.New("lastpass: config is nil")
	}
	if v, ok := raw["account_number"].(string); ok {
		cfg.AccountNumber = v
	}
	return cfg, nil
}

// DecodeSecrets pulls a typed Secrets out of the decrypted secrets payload.
func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	var s Secrets
	if raw == nil {
		return s, errors.New("lastpass: secrets is nil")
	}
	if v, ok := raw["provisioning_hash"].(string); ok {
		s.ProvisioningHash = v
	}
	return s, nil
}

// validate is the pure-local check for Config.
func (c Config) validate() error {
	if strings.TrimSpace(c.AccountNumber) == "" {
		return errors.New("lastpass: account_number is required")
	}
	return nil
}

// validate is the pure-local check for Secrets.
func (s Secrets) validate() error {
	if strings.TrimSpace(s.ProvisioningHash) == "" {
		return errors.New("lastpass: provisioning_hash is required")
	}
	return nil
}
