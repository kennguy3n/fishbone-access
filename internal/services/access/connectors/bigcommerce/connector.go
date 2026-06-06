// Package bigcommerce implements the access.AccessConnector contract for BigCommerce /v2/store/{store_hash}/v2/customers with X-Auth-Token header + page/limit pagination.
package bigcommerce

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
	ProviderName = "bigcommerce"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("bigcommerce: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	StoreHash string `json:"store_hash"`
}

type Secrets struct {
	Token string `json:"token"`
}

type BigCommerceAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *BigCommerceAccessConnector { return &BigCommerceAccessConnector{} }
func init()                            { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("bigcommerce: config is nil")
	}
	var cfg Config
	if v, ok := raw["store_hash"].(string); ok {
		cfg.StoreHash = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("bigcommerce: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.StoreHash) == "" {
		return errors.New("bigcommerce: store_hash is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("bigcommerce: token is required")
	}
	return nil
}

func (c *BigCommerceAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *BigCommerceAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.bigcommerce.com"
}

func (c *BigCommerceAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *BigCommerceAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Auth-Token", strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *BigCommerceAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("bigcommerce: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("bigcommerce: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *BigCommerceAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *BigCommerceAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}

	probe := c.baseURL() + ("/stores/" + url.PathEscape(cfg.StoreHash) + "/v2/customers") + "?page=1&limit=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("bigcommerce: connect probe: %w", err)
	}
	return nil
}

func (c *BigCommerceAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type bigcommerceUser struct {
	ID    json.Number `json:"id"`
	Email string      `json:"email"`
	Name  string      `json:"first_name"`
}

func (c *BigCommerceAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *BigCommerceAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	page := 1
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &page)
		if page < 1 {
			page = 1
		}
	}
	base := c.baseURL()
	path := base + ("/stores/" + url.PathEscape(cfg.StoreHash) + "/v2/customers")
	for {
		q := url.Values{
			"page":  []string{fmt.Sprintf("%d", page)},
			"limit": []string{fmt.Sprintf("%d", pageSize)},
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
		var items []bigcommerceUser
		if err := json.Unmarshal(body, &items); err != nil {
			return fmt.Errorf("bigcommerce: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(items))
		for _, u := range items {
			display := strings.TrimSpace(u.Name)
			if display == "" {
				display = u.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID.String(),
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      "active",
			})
		}
		next := ""
		if len(items) == pageSize {
			next = fmt.Sprintf("%d", page+1)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		page++
	}
}

func (c *BigCommerceAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *BigCommerceAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "x-auth-token",
		"token_short": shortToken(secrets.Token),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*BigCommerceAccessConnector)(nil)
