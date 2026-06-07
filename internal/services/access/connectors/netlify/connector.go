// Package netlify implements the access.AccessConnector contract for the
// Netlify account-membership API.
package netlify

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
	ProviderName   = "netlify"
	defaultBaseURL = "https://api.netlify.com"
)

var ErrNotImplemented = fmt.Errorf("netlify: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	AccountSlug string `json:"account_slug"`
}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type NetlifyAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *NetlifyAccessConnector { return &NetlifyAccessConnector{} }
func init()                        { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("netlify: config is nil")
	}
	var cfg Config
	if v, ok := raw["account_slug"].(string); ok {
		// Canonicalize at decode time so the slug interpolated into every
		// request path is the same value validate() checks and the metadata
		// reports, and so a padded " acme " cannot survive into the URL.
		cfg.AccountSlug = strings.TrimSpace(v)
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("netlify: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_token"].(string); ok {
		s.AccessToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	if c.AccountSlug == "" {
		return errors.New("netlify: account_slug is required")
	}
	return nil
}

// membersPath builds the base-relative account-members path. It is the
// single source of truth for the account-members route shared by the
// base operations (Connect/CountIdentities/SyncIdentities) and the
// advanced operations (which compose it into an absolute URL via
// membersURL). url.PathEscape guards against a slug containing '/',
// '%', or '?' corrupting the request path.
func membersPath(slug string) string {
	return "/api/v1/" + url.PathEscape(strings.TrimSpace(slug)) + "/members"
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("netlify: access_token is required")
	}
	return nil
}

func (c *NetlifyAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *NetlifyAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *NetlifyAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *NetlifyAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *NetlifyAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("netlify: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("netlify: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *NetlifyAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *NetlifyAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, membersPath(cfg.AccountSlug))
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("netlify: connect probe: %w", err)
	}
	return nil
}

func (c *NetlifyAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type netlifyMember struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	FullName string `json:"full_name,omitempty"`
	Role     string `json:"role"`
	Avatar   string `json:"avatar,omitempty"`
}

func (c *NetlifyAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, membersPath(cfg.AccountSlug))
	if err != nil {
		return 0, err
	}
	body, err := c.do(req)
	if err != nil {
		return 0, err
	}
	var members []netlifyMember
	if err := json.Unmarshal(body, &members); err != nil {
		return 0, fmt.Errorf("netlify: decode members: %w", err)
	}
	return len(members), nil
}

func (c *NetlifyAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, membersPath(cfg.AccountSlug))
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	var members []netlifyMember
	if err := json.Unmarshal(body, &members); err != nil {
		return fmt.Errorf("netlify: decode members: %w", err)
	}
	identities := make([]*access.Identity, 0, len(members))
	for _, m := range members {
		display := m.FullName
		if display == "" {
			display = m.Email
		}
		identities = append(identities, &access.Identity{
			ExternalID:  m.ID,
			Type:        access.IdentityTypeUser,
			DisplayName: display,
			Email:       m.Email,
			Status:      "active",
			RawData:     map[string]interface{}{"role": m.Role},
		})
	}
	return handler(identities, "")
}

// GetSSOMetadata returns the operator-supplied SAML metadata for
// Netlify team-level SSO (Business plan and above). When
// `sso_metadata_url` is blank the helper returns (nil, nil) and the
// caller gracefully downgrades.
func (c *NetlifyAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *NetlifyAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":     ProviderName,
		"account_slug": cfg.AccountSlug,
		"auth_type":    "access_token",
		"token_short":  shortToken(secrets.AccessToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*NetlifyAccessConnector)(nil)
