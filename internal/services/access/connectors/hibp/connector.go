// Package hibp implements the access.AccessConnector contract for the
// Have I Been Pwned (HIBP) breach-search API.
//
// HIBP is an audit-log-only / search-only data source: there is no
// per-tenant identity directory to enumerate. SyncIdentities therefore
// returns an empty batch immediately and CountIdentities reports zero.
// Validate / Connect still verify the API key against the public probe
// endpoint so the credential metadata can be persisted.
package hibp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const ProviderName = "hibp"

// ErrNotImplemented preserves the original sentinel for
// backward compatibility (existing tests use errors.Is against it).
// It wraps access.ErrCapabilityNotSupported so callers that switch
// to the canonical platform sentinel also match — HIBP only exposes
// a breach-lookup API, so ProvisionAccess / RevokeAccess / ListEntitlements
// are structurally absent, not "future TODO".
var ErrNotImplemented = fmt.Errorf("hibp: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	APIKey string `json:"api_key"`
}

type HIBPAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *HIBPAccessConnector { return &HIBPAccessConnector{} }
func init()                     { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("hibp: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("hibp: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_key"].(string); ok {
		s.APIKey = v
	}
	return s, nil
}

func (Config) validate() error { return nil }

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIKey) == "" {
		return errors.New("hibp: api_key is required")
	}
	return nil
}

func (c *HIBPAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *HIBPAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://haveibeenpwned.com"
}

func (c *HIBPAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *HIBPAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("hibp-api-key", strings.TrimSpace(secrets.APIKey))
	req.Header.Set("User-Agent", "shieldnet360-access")
	return req, nil
}

func (c *HIBPAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("hibp: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		// /breachedaccount returns 404 for accounts without breaches —
		// the credential is valid, so treat as success for the probe.
		return body, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("hibp: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *HIBPAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *HIBPAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/api/v3/subscription/status"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("hibp: connect probe: %w", err)
	}
	return nil
}

func (c *HIBPAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

// CountIdentities reports zero — HIBP is an audit-only / search-only API
// with no per-tenant identity directory to enumerate. Config and secrets
// are still validated so callers with invalid credentials receive a
// deterministic error instead of a silent success.
func (c *HIBPAccessConnector) CountIdentities(_ context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	if _, _, err := c.decodeBoth(configRaw, secretsRaw); err != nil {
		return 0, err
	}
	return 0, nil
}

// SyncIdentities is a no-op for HIBP. The handler is invoked once with an
// empty batch and an empty next-checkpoint so callers terminate cleanly.
func (c *HIBPAccessConnector) SyncIdentities(
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

func (c *HIBPAccessConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *HIBPAccessConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *HIBPAccessConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
	return nil, ErrNotImplemented
}
func (c *HIBPAccessConnector) GetSSOMetadata(_ context.Context, _, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return nil, nil
}

func (c *HIBPAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":  ProviderName,
		"auth_type": "api_key",
		"key_short": shortToken(secrets.APIKey),
		"sync_kind": "audit_only",
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return strings.Repeat("*", len(t))
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*HIBPAccessConnector)(nil)
