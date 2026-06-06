package google_workspace

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ProviderName is the registry key for the Google Workspace connector.
// Lowercased, snake_case per docs/architecture.md §3.
const ProviderName = "google_workspace"

// Config is the operator-visible configuration for a Google Workspace
// connector instance.
type Config struct {
	// Domain is the customer's primary Google Workspace domain (e.g.
	// "uney.com"). Used as the ?domain= filter on Admin SDK Directory API
	// list requests.
	Domain string `json:"domain"`
	// AdminEmail is the address of an admin user that the service account
	// impersonates via domain-wide delegation. Required for Admin SDK
	// access to work because most directory APIs reject service-account
	// principals directly.
	AdminEmail string `json:"admin_email"`
}

// Secrets is the secret material stored encrypted in
// access_connectors.credentials.
type Secrets struct {
	// ServiceAccountKey is the raw service-account JSON key blob exactly
	// as Google emits it (private_key, client_email, ...). Stored in
	// secrets so that the key material itself never lands in the
	// operator-visible Config jsonb.
	ServiceAccountKey string `json:"service_account_key"`
}

// DecodeConfig pulls a typed Config out of the operator-supplied payload.
func DecodeConfig(raw map[string]interface{}) (Config, error) {
	var cfg Config
	if raw == nil {
		return cfg, errors.New("google_workspace: config is nil")
	}
	if v, ok := raw["domain"].(string); ok {
		cfg.Domain = v
	}
	if v, ok := raw["admin_email"].(string); ok {
		cfg.AdminEmail = v
	}
	return cfg, nil
}

// DecodeSecrets pulls a typed Secrets out of the decrypted secrets payload.
func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	var s Secrets
	if raw == nil {
		return s, errors.New("google_workspace: secrets is nil")
	}
	if v, ok := raw["service_account_key"].(string); ok {
		s.ServiceAccountKey = v
	}
	return s, nil
}

// validate is the pure-local check for Config.
func (c Config) validate() error {
	if c.Domain == "" {
		return errors.New("google_workspace: domain is required")
	}
	if !strings.Contains(c.Domain, ".") {
		return fmt.Errorf("google_workspace: domain %q is not a valid DNS name", c.Domain)
	}
	if c.AdminEmail == "" {
		return errors.New("google_workspace: admin_email is required")
	}
	if !strings.Contains(c.AdminEmail, "@") {
		return fmt.Errorf("google_workspace: admin_email %q is not a valid email", c.AdminEmail)
	}
	return nil
}

// validate is the pure-local check for Secrets. It JSON-parses the supplied
// service-account key just enough to confirm shape — no network I/O, and the
// private key value is never logged.
func (s Secrets) validate() error {
	if s.ServiceAccountKey == "" {
		return errors.New("google_workspace: service_account_key is required")
	}
	var key serviceAccountKey
	if err := json.Unmarshal([]byte(s.ServiceAccountKey), &key); err != nil {
		return fmt.Errorf("google_workspace: service_account_key is not valid JSON: %w", err)
	}
	if key.Type != "service_account" {
		return fmt.Errorf("google_workspace: service_account_key.type = %q, want \"service_account\"", key.Type)
	}
	if key.ClientEmail == "" {
		return errors.New("google_workspace: service_account_key.client_email is required")
	}
	if key.PrivateKeyID == "" {
		return errors.New("google_workspace: service_account_key.private_key_id is required")
	}
	if key.PrivateKey == "" {
		return errors.New("google_workspace: service_account_key.private_key is required")
	}
	return nil
}

// serviceAccountKey is the minimal shape we validate and surface back to
// callers via GetCredentialsMetadata.
type serviceAccountKey struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	ClientID     string `json:"client_id"`
}
