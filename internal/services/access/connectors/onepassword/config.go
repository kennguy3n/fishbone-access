package onepassword

import (
	"errors"
	"net/url"
	"strings"
)

// ProviderName is the registry key for the 1Password connector.
const ProviderName = "onepassword"

// Config is the operator-visible configuration for a 1Password connector
// instance. AccountURL is the customer's 1Password account URL (used for
// the SCIM bridge), e.g. "https://uney.1password.com" or
// "https://uney.1password.eu". EventsAPIURL is the base URL of the
// 1Password Events Reporting API and defaults to
// "https://events.1password.com"; operators only need to override it
// for regional events endpoints (e.g. "https://events.1password.eu")
// or for tests against a mock server.
type Config struct {
	AccountURL   string `json:"account_url"`
	EventsAPIURL string `json:"events_api_url,omitempty"`
}

// defaultEventsAPIURL is the global 1Password Events Reporting API host.
// 1Password serves SCIM at scim.1password.com and audit events at
// events.1password.com — they are different services with different
// hosts. Keep them separate so requests do not hit the wrong service.
const defaultEventsAPIURL = "https://events.1password.com"

// Secrets holds the bearer credential used to authenticate against the
// 1Password SCIM bridge or Events API. Operators provide either a
// SCIMBridgeToken (most common) or a ServiceAccountToken.
type Secrets struct {
	SCIMBridgeToken     string `json:"scim_bridge_token,omitempty"`
	ServiceAccountToken string `json:"service_account_token,omitempty"`
}

// DecodeConfig pulls a typed Config out of the operator-supplied payload.
func DecodeConfig(raw map[string]interface{}) (Config, error) {
	var cfg Config
	if raw == nil {
		return cfg, errors.New("onepassword: config is nil")
	}
	if v, ok := raw["account_url"].(string); ok {
		cfg.AccountURL = v
	}
	if v, ok := raw["events_api_url"].(string); ok {
		cfg.EventsAPIURL = v
	}
	return cfg, nil
}

// DecodeSecrets pulls a typed Secrets out of the decrypted secrets payload.
func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	var s Secrets
	if raw == nil {
		return s, errors.New("onepassword: secrets is nil")
	}
	if v, ok := raw["scim_bridge_token"].(string); ok {
		s.SCIMBridgeToken = v
	}
	if v, ok := raw["service_account_token"].(string); ok {
		s.ServiceAccountToken = v
	}
	return s, nil
}

// validate is the pure-local check for Config.
func (c Config) validate() error {
	if c.AccountURL == "" {
		return errors.New("onepassword: account_url is required")
	}
	u, err := url.Parse(c.AccountURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("onepassword: account_url must be an absolute URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return errors.New("onepassword: account_url must use http or https")
	}
	if c.EventsAPIURL != "" {
		eu, err := url.Parse(c.EventsAPIURL)
		if err != nil || eu.Scheme == "" || eu.Host == "" {
			return errors.New("onepassword: events_api_url must be an absolute URL")
		}
		escheme := strings.ToLower(eu.Scheme)
		if escheme != "http" && escheme != "https" {
			return errors.New("onepassword: events_api_url must use http or https")
		}
	}
	return nil
}

// validate is the pure-local check for Secrets. Exactly one bearer token must
// be provided.
func (s Secrets) validate() error {
	if s.SCIMBridgeToken == "" && s.ServiceAccountToken == "" {
		return errors.New("onepassword: scim_bridge_token or service_account_token is required")
	}
	return nil
}

// bearerToken returns whichever token is set. SCIMBridgeToken takes
// precedence when both are populated.
func (s Secrets) bearerToken() string {
	if s.SCIMBridgeToken != "" {
		return s.SCIMBridgeToken
	}
	return s.ServiceAccountToken
}

// normalisedAccountURL strips a trailing slash for stable URL composition.
func (c Config) normalisedAccountURL() string {
	return strings.TrimRight(c.AccountURL, "/")
}

// normalisedEventsAPIURL returns the Events Reporting API base URL with
// any trailing slash stripped, falling back to the global default when
// the operator has not configured an override.
func (c Config) normalisedEventsAPIURL() string {
	if c.EventsAPIURL == "" {
		return defaultEventsAPIURL
	}
	return strings.TrimRight(c.EventsAPIURL, "/")
}
