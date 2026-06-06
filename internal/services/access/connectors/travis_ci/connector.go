// Package travis_ci implements the access.AccessConnector contract for the
// Travis CI /users API.
package travis_ci

import (
	"context"
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
	ProviderName = "travis_ci"
	pageSize     = 100
)

// ErrNotImplemented is retained as a public sentinel for backwards
// compatibility; all access capabilities are now implemented.
var ErrNotImplemented = fmt.Errorf("travis_ci: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	// Endpoint selects the public Travis CI API host. Empty string defaults
	// to https://api.travis-ci.com (the .com instance); set to .org for
	// the legacy open-source instance.
	Endpoint string `json:"endpoint"`
}

type Secrets struct {
	Token string `json:"token"`
}

type TravisCIAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *TravisCIAccessConnector { return &TravisCIAccessConnector{} }
func init()                         { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("travis_ci: config is nil")
	}
	var cfg Config
	if v, ok := raw["endpoint"].(string); ok {
		cfg.Endpoint = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("travis_ci: secrets is nil")
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
		return nil
	}
	// Endpoint is interpolated into the request URL where the bearer
	// token is sent, so an unvalidated value is an SSRF / token-leak
	// vector. Restrict to https:// URLs whose host is a DNS-shaped
	// domain (not an IP literal), with no userinfo, path, query, or
	// fragment. This still supports both the public Travis CI API
	// (api.travis-ci.com / api.travis-ci.org) and Travis CI Enterprise
	// installs at customer-controlled domains, while blocking the
	// classic SSRF target (e.g. http://169.254.169.254/...).
	u, err := url.Parse(e)
	if err != nil {
		return fmt.Errorf("travis_ci: endpoint must be a well-formed URL: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("travis_ci: endpoint must use https://")
	}
	if u.User != nil {
		return errors.New("travis_ci: endpoint must not contain userinfo")
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("travis_ci: endpoint must not contain a path")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("travis_ci: endpoint must not contain a query or fragment")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("travis_ci: endpoint must contain a host")
	}
	if net.ParseIP(host) != nil {
		return errors.New("travis_ci: endpoint host must be a domain name, not an IP literal")
	}
	if !isHost(host) {
		return errors.New("travis_ci: endpoint host must contain only DNS label characters and dots")
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
		return errors.New("travis_ci: token is required")
	}
	return nil
}

func (c *TravisCIAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *TravisCIAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	if e := strings.TrimSpace(cfg.Endpoint); e != "" {
		return strings.TrimRight(e, "/")
	}
	return "https://api.travis-ci.com"
}

func (c *TravisCIAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *TravisCIAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Travis-API-Version", "3")
	req.Header.Set("Authorization", "token "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *TravisCIAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("travis_ci: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("travis_ci: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *TravisCIAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *TravisCIAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := fmt.Sprintf("%s/users?limit=1&offset=0", c.baseURL(cfg))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("travis_ci: connect probe: %w", err)
	}
	return nil
}

func (c *TravisCIAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type travisUser struct {
	ID        json.Number `json:"id"`
	Login     string      `json:"login"`
	Name      string      `json:"name"`
	Email     string      `json:"email"`
	IsBlocked bool        `json:"is_blocked"`
}

type travisListResponse struct {
	Users []travisUser `json:"users"`
	At    struct {
		Limit  int `json:"limit"`
		Offset int `json:"offset"`
		Count  int `json:"count"`
	} `json:"@pagination"`
}

func (c *TravisCIAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *TravisCIAccessConnector) SyncIdentities(
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
		path := fmt.Sprintf("%s/users?limit=%d&offset=%d", base, pageSize, offset)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp travisListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("travis_ci: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Users))
		for _, u := range resp.Users {
			display := u.Name
			if display == "" {
				display = u.Login
			}
			if display == "" {
				display = u.Email
			}
			status := "active"
			if u.IsBlocked {
				status = "blocked"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID.String(),
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      status,
			})
		}
		next := ""
		if len(resp.Users) == pageSize && offset+pageSize < resp.At.Count {
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

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker Travis CI
// Enterprise SSO federation. When `sso_metadata_url` is blank the helper
// returns (nil, nil) and the caller gracefully downgrades.
func (c *TravisCIAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *TravisCIAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "token",
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

var _ access.AccessConnector = (*TravisCIAccessConnector)(nil)
