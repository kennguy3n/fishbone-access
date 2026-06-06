// Package tailscale implements the access.AccessConnector contract for the
// Tailscale tailnet users API.
package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName   = "tailscale"
	defaultBaseURL = "https://api.tailscale.com"
)

var ErrNotImplemented = fmt.Errorf("tailscale: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Tailnet string `json:"tailnet"`
}

type Secrets struct {
	APIKey string `json:"api_key"`
}

type TailscaleAccessConnector struct {
	httpClient   func() httpDoer
	urlOverride  string
	timeOverride func() time.Time
}

func New() *TailscaleAccessConnector { return &TailscaleAccessConnector{} }
func init()                          { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("tailscale: config is nil")
	}
	var cfg Config
	if v, ok := raw["tailnet"].(string); ok {
		cfg.Tailnet = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("tailscale: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_key"].(string); ok {
		s.APIKey = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.Tailnet) == "" {
		return errors.New("tailscale: tailnet is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIKey) == "" {
		return errors.New("tailscale: api_key is required")
	}
	return nil
}

func decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *TailscaleAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, _, err := decodeBoth(configRaw, secretsRaw)
	return err
}

func (c *TailscaleAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *TailscaleAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *TailscaleAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	// Tailscale supports HTTP Basic with the API key as username and
	// empty password; this is the documented auth model.
	req.SetBasicAuth(strings.TrimSpace(secrets.APIKey), "")
	return req, nil
}

func (c *TailscaleAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("tailscale: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("tailscale: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *TailscaleAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/api/v2/tailnet/"+url.PathEscape(cfg.Tailnet)+"/users")
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("tailscale: connect probe: %w", err)
	}
	return nil
}

func (c *TailscaleAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type tsUser struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	LoginName   string `json:"loginName"`
	Status      string `json:"status"`
	Type        string `json:"type"`
}

type tsUsersResponse struct {
	Users []tsUser `json:"users"`
}

func (c *TailscaleAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/api/v2/tailnet/"+url.PathEscape(cfg.Tailnet)+"/users")
	if err != nil {
		return 0, err
	}
	body, err := c.do(req)
	if err != nil {
		return 0, err
	}
	var resp tsUsersResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, fmt.Errorf("tailscale: decode users: %w", err)
	}
	return len(resp.Users), nil
}

func (c *TailscaleAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/api/v2/tailnet/"+url.PathEscape(cfg.Tailnet)+"/users")
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	var resp tsUsersResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("tailscale: decode users: %w", err)
	}
	identities := make([]*access.Identity, 0, len(resp.Users))
	for _, u := range resp.Users {
		display := u.DisplayName
		if display == "" {
			display = u.LoginName
		}
		idType := access.IdentityTypeUser
		if u.Type == "service" || u.Type == "shared" {
			idType = access.IdentityTypeServiceAccount
		}
		identities = append(identities, &access.Identity{
			ExternalID:  u.ID,
			Type:        idType,
			DisplayName: display,
			Email:       u.LoginName,
			Status:      strings.ToLower(u.Status),
		})
	}
	return handler(identities, "")
}

// GetSSOMetadata returns the operator-supplied OIDC metadata for the
// Tailscale tenant. Tailscale federates SSO via the tailnet's identity
// provider settings (Okta / Azure AD / Google / OIDC). When
// `sso_metadata_url` is blank the helper returns (nil, nil) and the
// caller gracefully downgrades.
func (c *TailscaleAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "oidc"), nil
}

func (c *TailscaleAccessConnector) GetCredentialsMetadata(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{
		"provider":  ProviderName,
		"tailnet":   cfg.Tailnet,
		"key_short": shortKey(secrets.APIKey),
	}
	return out, nil
}

func shortKey(key string) string {
	key = strings.TrimSpace(key)
	if len(key) <= 8 {
		return key
	}
	return key[:4] + "..." + key[len(key)-4:]
}

var _ access.AccessConnector = (*TailscaleAccessConnector)(nil)
