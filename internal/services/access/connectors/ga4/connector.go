// Package ga4 implements the access.AccessConnector contract for the
// Google Analytics 4 Admin /v1beta/accounts/{account}/userLinks endpoint
// with OAuth2 bearer auth and pageSize/pageToken pagination.
package ga4

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
	ProviderName = "ga4"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("ga4: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Account string `json:"account"`
}

type Secrets struct {
	Token string `json:"token"`
}

type GA4AccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *GA4AccessConnector { return &GA4AccessConnector{} }
func init()                    { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("ga4: config is nil")
	}
	var cfg Config
	if v, ok := raw["account"].(string); ok {
		cfg.Account = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("ga4: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.Account) == "" {
		return errors.New("ga4: account is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("ga4: token is required")
	}
	return nil
}

func (c *GA4AccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *GA4AccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://analyticsadmin.googleapis.com"
}

func (c *GA4AccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *GA4AccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *GA4AccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("ga4: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ga4: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *GA4AccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *GA4AccessConnector) userLinksPath(cfg Config) string {
	return "/v1beta/accounts/" + url.PathEscape(strings.TrimSpace(cfg.Account)) + "/userLinks"
}

func (c *GA4AccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + c.userLinksPath(cfg) + "?pageSize=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("ga4: connect probe: %w", err)
	}
	return nil
}

func (c *GA4AccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type ga4UserLink struct {
	Name         string   `json:"name"`
	EmailAddress string   `json:"emailAddress"`
	DirectRoles  []string `json:"directRoles"`
}

type ga4ListResponse struct {
	UserLinks     []ga4UserLink `json:"userLinks"`
	NextPageToken string        `json:"nextPageToken"`
}

func (c *GA4AccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *GA4AccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(checkpoint)
	base := c.baseURL()
	path := c.userLinksPath(cfg)
	for {
		q := url.Values{
			"pageSize": []string{fmt.Sprintf("%d", pageSize)},
		}
		if token != "" {
			q.Set("pageToken", token)
		}
		fullURL := base + path + "?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp ga4ListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("ga4: decode userLinks: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.UserLinks))
		for _, u := range resp.UserLinks {
			// GA4 admin users are identified by emailAddress (the field
			// accepted by accounts.userLinks.create). The advanced-cap
			// methods accept the same value via grant.UserExternalID and
			// resolve it to the auto-generated resource name client-side
			// (see findUserLinkByExternalID in advanced.go). The opaque
			// resource name is preserved in RawData under "name" for
			// callers that already have it and want to address the
			// userLink directly.
			//
			// BREAKING CHANGE (PR #52): prior versions of this connector
			// returned Identity.ExternalID = u.Name (the resource name).
			// The change canonicalises ExternalID on the email so it is
			// stable across SyncIdentities / Provision / Revoke / List —
			// previously the same admin user surfaced under two distinct
			// identifiers depending on the API path that produced it.
			// Consumers that cached the prior resource-name ExternalID
			// can keep passing it through grant.UserExternalID: the
			// advanced-cap helpers detect the `accounts/*/userLinks/*`
			// shape and take a direct-GET fast path
			// (advanced.go:findUserLinkByExternalID), preserving wire
			// compatibility at the API layer.
			email := strings.TrimSpace(u.EmailAddress)
			name := strings.TrimSpace(u.Name)
			external := email
			if external == "" {
				external = name
			}
			display := email
			if display == "" {
				display = name
			}
			raw := map[string]interface{}{}
			if name != "" {
				raw["name"] = name
			}
			identities = append(identities, &access.Identity{
				ExternalID:  external,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.EmailAddress,
				Status:      "active",
				RawData:     raw,
			})
		}
		if err := handler(identities, resp.NextPageToken); err != nil {
			return err
		}
		if resp.NextPageToken == "" {
			return nil
		}
		token = resp.NextPageToken
	}
}

// GetSSOMetadata surfaces operator-supplied SAML metadata for the
// Google Analytics 4 admin account. Google Analytics federates SSO via
// Google Workspace / Cloud Identity SAML; the connector forwards
// operator-supplied URLs verbatim via access.SSOMetadataFromConfig so the
// SSOFederationService can register a iam-core SAML broker. Returns
// (nil, nil) when the operator has not supplied a metadata URL so the
// caller downgrades gracefully.
func (c *GA4AccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *GA4AccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "oauth2_bearer",
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

var _ access.AccessConnector = (*GA4AccessConnector)(nil)
