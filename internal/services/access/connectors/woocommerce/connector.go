// Package woocommerce implements the access.AccessConnector contract for WooCommerce /wp-json/wc/v3/customers with HTTP Basic consumer_key:consumer_secret + page/per_page pagination.
package woocommerce

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

const (
	ProviderName = "woocommerce"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("woocommerce: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Endpoint string `json:"endpoint"`
}

type Secrets struct {
	ConsumerKey    string `json:"consumer_key"`
	ConsumerSecret string `json:"consumer_secret"`
}

type WooCommerceAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *WooCommerceAccessConnector { return &WooCommerceAccessConnector{} }
func init()                            { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("woocommerce: config is nil")
	}
	var cfg Config
	if v, ok := raw["endpoint"].(string); ok {
		cfg.Endpoint = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("woocommerce: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["consumer_key"].(string); ok {
		s.ConsumerKey = v
	}
	if v, ok := raw["consumer_secret"].(string); ok {
		s.ConsumerSecret = v
	}
	return s, nil
}

func (c Config) validate() error {
	e := strings.TrimSpace(c.Endpoint)
	if e == "" {
		return errors.New("woocommerce: endpoint is required")
	}
	u, err := url.Parse(e)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("woocommerce: endpoint must be an https URL")
	}
	if u.User != nil {
		return errors.New("woocommerce: endpoint must not embed credentials")
	}
	host := u.Hostname()
	if net.ParseIP(host) != nil {
		return errors.New("woocommerce: endpoint must not be an IP literal")
	}
	if !isHost(host) {
		return errors.New("woocommerce: endpoint host is invalid")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.ConsumerKey) == "" {
		return errors.New("woocommerce: consumer_key is required")
	}
	if strings.TrimSpace(s.ConsumerSecret) == "" {
		return errors.New("woocommerce: consumer_secret is required")
	}
	return nil
}

func (c *WooCommerceAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *WooCommerceAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
}

func (c *WooCommerceAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *WooCommerceAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	creds := strings.TrimSpace(secrets.ConsumerKey) + ":" + strings.TrimSpace(secrets.ConsumerSecret)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *WooCommerceAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("woocommerce: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("woocommerce: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *WooCommerceAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *WooCommerceAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}

	probe := c.baseURL(cfg) + ("/wp-json/wc/v3/customers") + "?page=1&per_page=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("woocommerce: connect probe: %w", err)
	}
	return nil
}

func (c *WooCommerceAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type woocommerceUser struct {
	ID    json.Number `json:"id"`
	Email string      `json:"email"`
	Name  string      `json:"first_name"`
}

func (c *WooCommerceAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *WooCommerceAccessConnector) SyncIdentities(
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
	base := c.baseURL(cfg)
	path := base + ("/wp-json/wc/v3/customers")
	for {
		q := url.Values{
			"page":     []string{fmt.Sprintf("%d", page)},
			"per_page": []string{fmt.Sprintf("%d", pageSize)},
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
		var items []woocommerceUser
		if err := json.Unmarshal(body, &items); err != nil {
			return fmt.Errorf("woocommerce: decode users: %w", err)
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

func (c *WooCommerceAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *WooCommerceAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":              ProviderName,
		"auth_type":             "basic",
		"consumer_key_short":    shortToken(secrets.ConsumerKey),
		"consumer_secret_short": shortToken(secrets.ConsumerSecret),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
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

var _ access.AccessConnector = (*WooCommerceAccessConnector)(nil)
