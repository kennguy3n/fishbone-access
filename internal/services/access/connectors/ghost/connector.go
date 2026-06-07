// Package ghost implements the access.AccessConnector contract for Ghost /ghost/api/admin/users/
// with bearer auth + page/limit pagination.
package ghost

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
	ProviderName = "ghost"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("ghost: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config holds the per-tenant Ghost connection settings. BaseURL is the
// operator's Ghost site root (e.g. "https://blog.example.com"); the Admin
// API lives under "{BaseURL}/ghost/api/admin/". Ghost is self-hosted per
// customer, so there is no shared default host — BaseURL is required.
type Config struct {
	BaseURL string `json:"base_url"`
}

type Secrets struct {
	Token string `json:"token"`
}

type GhostAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *GhostAccessConnector { return &GhostAccessConnector{} }
func init()                      { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("ghost: config is nil")
	}
	var cfg Config
	if v, ok := raw["base_url"].(string); ok {
		cfg.BaseURL = strings.TrimSpace(v)
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("ghost: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (c Config) validate() error {
	if c.BaseURL == "" {
		return errors.New("ghost: base_url is required (your Ghost site URL, e.g. https://blog.example.com)")
	}
	if !strings.HasPrefix(c.BaseURL, "http://") && !strings.HasPrefix(c.BaseURL, "https://") {
		return errors.New("ghost: base_url must include scheme (http:// or https://)")
	}
	return nil
}
func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("ghost: token is required")
	}
	return nil
}

func (c *GhostAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *GhostAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return strings.TrimRight(cfg.BaseURL, "/")
}

// sharedHTTPClient is reused across requests so the underlying
// http.Transport connection pool (keep-alives, TLS sessions) is shared
// rather than rebuilt on every call. http.Client is safe for concurrent
// use by multiple goroutines.
var sharedHTTPClient = &http.Client{Timeout: 30 * time.Second}

func (c *GhostAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return sharedHTTPClient
}

func (c *GhostAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *GhostAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("ghost: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ghost: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *GhostAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *GhostAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL(cfg) + ("/ghost/api/admin/users/") + "?page=1&limit=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("ghost: connect probe: %w", err)
	}
	return nil
}

func (c *GhostAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type apiUser struct {
	ID    json.Number `json:"id"`
	Email string      `json:"email"`
	Name  string      `json:"name"`
}

type apiListResponse struct {
	Items []apiUser `json:"users"`
}

func (c *GhostAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *GhostAccessConnector) SyncIdentities(
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
	pathOnly := base + ("/ghost/api/admin/users/")
	for {
		q := url.Values{
			"page":  []string{fmt.Sprintf("%d", page)},
			"limit": []string{fmt.Sprintf("%d", pageSize)},
		}
		fullURL := pathOnly + "?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp apiListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("ghost: decode users: %w", err)
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
		next := ""
		if len(resp.Items) == pageSize {
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

func (c *GhostAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *GhostAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "bearer",
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

var _ access.AccessConnector = (*GhostAccessConnector)(nil)
