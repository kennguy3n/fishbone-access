// Package wufoo implements the access.AccessConnector contract for Wufoo
// /api/v3/users.json with HTTP Basic api_key auth (api_key as username, empty
// password) over a per-subdomain base URL.
package wufoo

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
	ProviderName = "wufoo"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("wufoo: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Subdomain string `json:"subdomain"`
}

type Secrets struct {
	APIKey string `json:"api_key"`
}

type WufooAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *WufooAccessConnector { return &WufooAccessConnector{} }
func init()                      { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("wufoo: config is nil")
	}
	var cfg Config
	if v, ok := raw["subdomain"].(string); ok {
		cfg.Subdomain = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("wufoo: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_key"].(string); ok {
		s.APIKey = v
	}
	return s, nil
}

func (c Config) validate() error {
	sd := strings.TrimSpace(c.Subdomain)
	if sd == "" {
		return errors.New("wufoo: subdomain is required")
	}
	if !isDNSLabel(sd) {
		return errors.New("wufoo: subdomain must be a single DNS label (letters, digits, hyphen)")
	}
	return nil
}

func isDNSLabel(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return false
		}
	}
	return s[0] != '-' && s[len(s)-1] != '-'
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIKey) == "" {
		return errors.New("wufoo: api_key is required")
	}
	return nil
}

func (c *WufooAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *WufooAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://" + strings.TrimSpace(cfg.Subdomain) + ".wufoo.com"
}

func (c *WufooAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *WufooAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	// Wufoo HTTP Basic: API key as username, empty password.
	req.SetBasicAuth(strings.TrimSpace(secrets.APIKey), "")
	return req, nil
}

func (c *WufooAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("wufoo: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("wufoo: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *WufooAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *WufooAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL(cfg) + "/api/v3/users.json?pageStart=0&pageSize=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("wufoo: connect probe: %w", err)
	}
	return nil
}

func (c *WufooAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type wufooUser struct {
	UserID    json.Number `json:"UserID"`
	User      string      `json:"User"`
	Email     string      `json:"Email"`
	FirstName string      `json:"FirstName"`
	LastName  string      `json:"LastName"`
}

type wufooListResponse struct {
	Users []wufooUser `json:"Users"`
}

func (c *WufooAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *WufooAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	offset := 0
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &offset)
		if offset < 0 {
			offset = 0
		}
	}
	base := c.baseURL(cfg)
	for {
		q := url.Values{
			"pageStart": []string{fmt.Sprintf("%d", offset)},
			"pageSize":  []string{fmt.Sprintf("%d", pageSize)},
		}
		fullURL := base + "/api/v3/users.json?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp wufooListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("wufoo: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Users))
		for _, u := range resp.Users {
			display := strings.TrimSpace(strings.TrimSpace(u.FirstName) + " " + strings.TrimSpace(u.LastName))
			if display == "" {
				display = u.User
			}
			if display == "" {
				display = u.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.UserID.String(),
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      "active",
			})
		}
		next := ""
		if len(resp.Users) == pageSize {
			next = fmt.Sprintf("%d", offset+pageSize)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset += pageSize
	}
}

// GetSSOMetadata surfaces operator-supplied SAML metadata for the
// Wufoo workspace. Wufoo (SurveyMonkey-owned) supports SAML 2.0 SSO via
// the admin console; the connector forwards operator-supplied URLs verbatim
// via access.SSOMetadataFromConfig so the SSOFederationService can register
// a iam-core SAML broker. Returns (nil, nil) when the operator has not
// supplied a metadata URL so the caller downgrades gracefully.
func (c *WufooAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *WufooAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":      ProviderName,
		"auth_type":     "http_basic_api_key",
		"api_key_short": shortToken(secrets.APIKey),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*WufooAccessConnector)(nil)
