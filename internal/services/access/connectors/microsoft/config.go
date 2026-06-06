package microsoft

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ProviderName is the registry key for the Microsoft Entra ID connector.
// Lowercased, snake_case per docs/architecture.md §3.
const ProviderName = "microsoft"

// Config is the operator-visible configuration for an Entra ID connector
// instance, persisted in access_connectors.config.
type Config struct {
	// TenantID is the Microsoft Entra directory (tenant) UUID. Used as the
	// path segment in the OAuth2 token endpoint
	// (https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token) and
	// in the OIDC discovery URL.
	TenantID string `json:"tenant_id"`
	// ClientID is the application (client) UUID of the Entra app registration.
	ClientID string `json:"client_id"`
}

// Secrets is the secret material stored encrypted in access_connectors.credentials.
type Secrets struct {
	// ClientSecret is the Entra app-registration client secret.
	ClientSecret string `json:"client_secret"`
}

// DecodeConfig pulls a typed Config out of the operator-supplied
// map[string]interface{} payload. Unknown fields are tolerated so that
// future schema additions do not break older rows.
func DecodeConfig(raw map[string]interface{}) (Config, error) {
	var cfg Config
	if raw == nil {
		return cfg, errors.New("microsoft: config is nil")
	}

	if v, ok := raw["tenant_id"].(string); ok {
		cfg.TenantID = v
	}
	if v, ok := raw["client_id"].(string); ok {
		cfg.ClientID = v
	}
	return cfg, nil
}

// DecodeSecrets pulls a typed Secrets out of the encrypted-then-decrypted
// secrets payload. Returns an error only on missing required fields.
func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	var s Secrets
	if raw == nil {
		return s, errors.New("microsoft: secrets is nil")
	}
	if v, ok := raw["client_secret"].(string); ok {
		s.ClientSecret = v
	}
	return s, nil
}

// validateConfig is the pure-local check for Config. Used by Validate; never
// performs network I/O.
func (c Config) validate() error {
	if c.TenantID == "" {
		return errors.New("microsoft: tenant_id is required")
	}
	if _, err := uuid.Parse(c.TenantID); err != nil {
		return fmt.Errorf("microsoft: tenant_id is not a valid UUID: %w", err)
	}
	if c.ClientID == "" {
		return errors.New("microsoft: client_id is required")
	}
	if _, err := uuid.Parse(c.ClientID); err != nil {
		return fmt.Errorf("microsoft: client_id is not a valid UUID: %w", err)
	}
	return nil
}

// validate is the pure-local check for Secrets.
func (s Secrets) validate() error {
	if s.ClientSecret == "" {
		return errors.New("microsoft: client_secret is required")
	}
	return nil
}
