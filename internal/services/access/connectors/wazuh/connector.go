// Package wazuh implements the access.AccessConnector contract for the
// Wazuh /security/users API.
//
// Wazuh ships with a self-managed RBAC realm whose users are typically
// SIEM operators rather than tenant identities the platform needs to
// enumerate, so SyncIdentities returns an empty batch immediately and
// CountIdentities reports zero. The platform does still provision
// against that operator realm: advanced.go uses
// /security/users/{user_id}/roles to back real ProvisionAccess /
// RevokeAccess / ListEntitlements implementations. Validate / Connect
// verify the bearer token against the security/users probe endpoint.
//
// The Wazuh API is reached over an operator-controlled, often
// self-signed HTTPS endpoint, so Config.Endpoint is required and the
// validator restricts it to a well-formed `https://` URL with a
// DNS-shaped host (no IP literals, userinfo, path, query, or fragment),
// matching the Travis CI pattern.
package wazuh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const ProviderName = "wazuh"

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	// Endpoint is the operator-controlled Wazuh API URL (e.g.
	// https://wazuh.corp.example:55000). Required.
	Endpoint string `json:"endpoint"`
}

type Secrets struct {
	Token string `json:"token"`
}

type WazuhAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *WazuhAccessConnector { return &WazuhAccessConnector{} }
func init()                      { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("wazuh: config is nil")
	}
	var cfg Config
	if v, ok := raw["endpoint"].(string); ok {
		cfg.Endpoint = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("wazuh: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (c Config) validate() error {
	e := strings.TrimSpace(c.Endpoint)
	if e == "" {
		return errors.New("wazuh: endpoint is required")
	}
	u, err := url.Parse(e)
	if err != nil {
		return fmt.Errorf("wazuh: endpoint must be a well-formed URL: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("wazuh: endpoint must use https://")
	}
	if u.User != nil {
		return errors.New("wazuh: endpoint must not contain userinfo")
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("wazuh: endpoint must not contain a path")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("wazuh: endpoint must not contain a query or fragment")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("wazuh: endpoint must contain a host")
	}
	if net.ParseIP(host) != nil {
		return errors.New("wazuh: endpoint host must be a domain name, not an IP literal")
	}
	if !isHost(host) {
		return errors.New("wazuh: endpoint host must contain only DNS label characters and dots")
	}
	return nil
}

func isHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z':
			case r >= 'A' && r <= 'Z':
			case r >= '0' && r <= '9':
			case r == '-':
			default:
				return false
			}
		}
	}
	return true
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("wazuh: token is required")
	}
	return nil
}

func (c *WazuhAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return err
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return err
	}
	return s.validate()
}

func (c *WazuhAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
}

func (c *WazuhAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *WazuhAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *WazuhAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("wazuh: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("wazuh: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *WazuhAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return Config{}, Secrets{}, err
	}
	if err := cfg.validate(); err != nil {
		return Config{}, Secrets{}, err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return Config{}, Secrets{}, err
	}
	if err := s.validate(); err != nil {
		return Config{}, Secrets{}, err
	}
	return cfg, s, nil
}

func (c *WazuhAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL(cfg) + "/security/users?limit=1&offset=0"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("wazuh: connect probe: %w", err)
	}
	return nil
}

func (c *WazuhAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

// CountIdentities reports zero — Wazuh's `/security/users` realm covers
// SIEM operators rather than tenant identities, so the connector is
// audit-focused and does not enumerate identities. Config and secrets
// are still validated so callers with invalid credentials receive a
// deterministic error instead of a silent success.
func (c *WazuhAccessConnector) CountIdentities(_ context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	if _, _, err := c.decodeBoth(configRaw, secretsRaw); err != nil {
		return 0, err
	}
	return 0, nil
}

// SyncIdentities is a no-op for Wazuh — invokes the handler with an empty
// batch and terminates. The connector is intended for audit-event ingest;
// the security/users realm is not the tenant identity directory.
func (c *WazuhAccessConnector) SyncIdentities(
	_ context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	if _, _, err := c.decodeBoth(configRaw, secretsRaw); err != nil {
		return err
	}
	// Non-nil empty slice per SyncIdentities empty-batch contract — see
	// types.go.
	return handler([]*access.Identity{}, "")
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker Wazuh
// XDR SSO federation. When `sso_metadata_url` is blank the helper
// returns (nil, nil) and the caller gracefully downgrades.
func (c *WazuhAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *WazuhAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "bearer",
		"token_short": shortToken(secrets.Token),
		"sync_kind":   "audit_only",
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*WazuhAccessConnector)(nil)
