// Package virustotal implements the access.AccessConnector contract for the
// VirusTotal v3 API.
//
// VirusTotal is an audit / lookup data source: there is no per-tenant
// identity *directory* to enumerate via the public API, so
// SyncIdentities returns an empty batch immediately and CountIdentities
// reports zero. However, VirusTotal Premium does expose a per-group
// membership API at /api/v3/groups/{group_id}/relationships/users that
// the platform uses to back real ProvisionAccess / RevokeAccess /
// ListEntitlements implementations (see advanced.go). Validate / Connect
// verify the API key against the public probe endpoint.
package virustotal

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

const ProviderName = "virustotal"

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	APIKey string `json:"api_key"`
}

type VirusTotalAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *VirusTotalAccessConnector { return &VirusTotalAccessConnector{} }
func init()                           { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("virustotal: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("virustotal: secrets is nil")
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
		return errors.New("virustotal: api_key is required")
	}
	return nil
}

func (c *VirusTotalAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *VirusTotalAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://www.virustotal.com"
}

func (c *VirusTotalAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *VirusTotalAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-apikey", strings.TrimSpace(secrets.APIKey))
	return req, nil
}

func (c *VirusTotalAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("virustotal: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("virustotal: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *VirusTotalAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *VirusTotalAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/api/v3/users/current"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("virustotal: connect probe: %w", err)
	}
	return nil
}

func (c *VirusTotalAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

// CountIdentities reports zero — VirusTotal exposes no per-tenant identity
// directory through the v3 API; the connector is audit-/lookup-only.
// Config and secrets are still validated so callers with invalid
// credentials receive a deterministic error instead of a silent success.
func (c *VirusTotalAccessConnector) CountIdentities(_ context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	if _, _, err := c.decodeBoth(configRaw, secretsRaw); err != nil {
		return 0, err
	}
	return 0, nil
}

// SyncIdentities is a no-op for VirusTotal — invokes the handler with an
// empty batch and terminates.
func (c *VirusTotalAccessConnector) SyncIdentities(
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

func (c *VirusTotalAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *VirusTotalAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
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
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*VirusTotalAccessConnector)(nil)
