// Package chargebee implements the access.AccessConnector contract for Chargebee /api/v2/customers with HTTP Basic site_api_key: + offset cursor pagination.
package chargebee

import (
	"context"
	"encoding/base64"
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
	ProviderName = "chargebee"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("chargebee: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Site string `json:"site"`
}

type Secrets struct {
	APIKey string `json:"api_key"`
}

type ChargebeeAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *ChargebeeAccessConnector { return &ChargebeeAccessConnector{} }
func init()                          { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("chargebee: config is nil")
	}
	var cfg Config
	if v, ok := raw["site"].(string); ok {
		cfg.Site = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("chargebee: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_key"].(string); ok {
		s.APIKey = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.Site) == "" {
		return errors.New("chargebee: site is required")
	}
	if !isDNSLabel(c.Site) {
		return errors.New("chargebee: site must be a single DNS label")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIKey) == "" {
		return errors.New("chargebee: api_key is required")
	}
	return nil
}

func (c *ChargebeeAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *ChargebeeAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://" + cfg.Site + ".chargebee.com"
}

func (c *ChargebeeAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *ChargebeeAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	creds := strings.TrimSpace(secrets.APIKey) + ":"
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *ChargebeeAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("chargebee: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("chargebee: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *ChargebeeAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *ChargebeeAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}

	probe := c.baseURL(cfg) + ("/api/v2/customers") + "?limit=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("chargebee: connect probe: %w", err)
	}
	return nil
}

func (c *ChargebeeAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type chargebeeUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"first_name"`
}

type chargebeeWrappedCustomer struct {
	Customer chargebeeUser `json:"customer"`
}

type chargebeeListResponse struct {
	List       []chargebeeWrappedCustomer `json:"list"`
	NextOffset string                     `json:"next_offset"`
}

func (c *ChargebeeAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *ChargebeeAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	offsetCursor := strings.TrimSpace(checkpoint)
	base := c.baseURL(cfg)
	path := base + ("/api/v2/customers")
	for {
		q := url.Values{
			"limit": []string{fmt.Sprintf("%d", pageSize)},
		}
		if offsetCursor != "" {
			q.Set("offset", offsetCursor)
		}
		fullURL := path + "?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp chargebeeListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("chargebee: decode customers: %w", err)
		}
		items := make([]chargebeeUser, 0, len(resp.List))
		for _, w := range resp.List {
			items = append(items, w.Customer)
		}
		identities := make([]*access.Identity, 0, len(items))
		for _, u := range items {
			display := strings.TrimSpace(u.Name)
			if display == "" {
				display = u.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      "active",
			})
		}
		next := ""
		if strings.TrimSpace(resp.NextOffset) != "" {
			next = strings.TrimSpace(resp.NextOffset)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offsetCursor = next
	}
}

// GetSSOMetadata returns the operator-supplied SAML metadata URL if
// configured. Chargebee federates SSO via SAML 2.0; when
// `sso_metadata_url` is blank the helper returns nil so callers
// gracefully downgrade.
func (c *ChargebeeAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *ChargebeeAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":      ProviderName,
		"auth_type":     "basic",
		"api_key_short": shortToken(secrets.APIKey),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		// Never echo a short secret verbatim: GetCredentialsMetadata is a
		// non-sensitive fingerprint surfaced in the admin UI/logs, so a
		// ≤8-char token must be fully masked rather than returned as-is.
		return strings.Repeat("*", len(t))
	}
	return t[:4] + "..." + t[len(t)-4:]
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

var _ access.AccessConnector = (*ChargebeeAccessConnector)(nil)
