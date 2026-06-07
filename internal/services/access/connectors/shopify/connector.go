// Package shopify implements the access.AccessConnector contract for Shopify /admin/api/2024-01/users.json with X-Shopify-Access-Token header + page_info cursor pagination.
package shopify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName = "shopify"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("shopify: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Shop string `json:"shop"`
}

type Secrets struct {
	Token string `json:"token"`
}

type ShopifyAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *ShopifyAccessConnector { return &ShopifyAccessConnector{} }
func init()                        { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("shopify: config is nil")
	}
	var cfg Config
	if v, ok := raw["shop"].(string); ok {
		cfg.Shop = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("shopify: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.Shop) == "" {
		return errors.New("shopify: shop is required")
	}
	if !isDNSLabel(c.Shop) {
		return errors.New("shopify: shop must be a single DNS label")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("shopify: token is required")
	}
	return nil
}

func (c *ShopifyAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *ShopifyAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://" + cfg.Shop + ".myshopify.com"
}

func (c *ShopifyAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *ShopifyAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Shopify-Access-Token", strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *ShopifyAccessConnector) do(req *http.Request) ([]byte, error) {
	body, _, err := c.doWithHeader(req)
	return body, err
}

// doWithHeader performs the request and returns the body together with
// the response headers so callers can read the RFC 5988 `Link` header
// Shopify uses for cursor pagination.
func (c *ShopifyAccessConnector) doWithHeader(req *http.Request) ([]byte, http.Header, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("shopify: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("shopify: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, resp.Header, nil
}

func (c *ShopifyAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *ShopifyAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}

	probe := c.baseURL(cfg) + ("/admin/api/2024-01/users.json") + "?limit=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("shopify: connect probe: %w", err)
	}
	return nil
}

func (c *ShopifyAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type shopifyUser struct {
	ID    json.Number `json:"id"`
	Email string      `json:"email"`
	Name  string      `json:"first_name"`
}

type shopifyListResponse struct {
	Items []shopifyUser `json:"users"`
}

// shopifyLinkNextPattern captures the URL of the rel="next" entry in a
// Shopify Link header, e.g.
//
//	<https://shop.myshopify.com/admin/api/2024-01/users.json?limit=100&page_info=abc>; rel="next"
var shopifyLinkNextPattern = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="next"`)

// nextPageInfoFromLink extracts the page_info cursor from the rel="next"
// entry of a Shopify Link header. It returns "" when there is no next
// page, which terminates pagination.
func nextPageInfoFromLink(linkHeader string) string {
	if strings.TrimSpace(linkHeader) == "" {
		return ""
	}
	m := shopifyLinkNextPattern.FindStringSubmatch(linkHeader)
	if len(m) < 2 {
		return ""
	}
	u, err := url.Parse(m[1])
	if err != nil {
		return ""
	}
	return u.Query().Get("page_info")
}

func (c *ShopifyAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *ShopifyAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	pageInfo := strings.TrimSpace(checkpoint)
	base := c.baseURL(cfg)
	path := base + ("/admin/api/2024-01/users.json")
	for {
		q := url.Values{
			"limit": []string{fmt.Sprintf("%d", pageSize)},
		}
		if pageInfo != "" {
			q.Set("page_info", pageInfo)
		}
		fullURL := path + "?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		body, header, err := c.doWithHeader(req)
		if err != nil {
			return err
		}
		var resp shopifyListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("shopify: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Items))
		for _, u := range resp.Items {
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
		next := nextPageInfoFromLink(header.Get("Link"))
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		pageInfo = next
	}
}

func (c *ShopifyAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *ShopifyAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "x-shopify-access-token",
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

var _ access.AccessConnector = (*ShopifyAccessConnector)(nil)
