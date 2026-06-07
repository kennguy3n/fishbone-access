// Package snyk implements the access.AccessConnector contract for the
// Snyk REST org members API.
package snyk

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

	"bytes"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName   = "snyk"
	defaultBaseURL = "https://api.snyk.io"
	apiVersion     = "2024-08-25"
	pageLimit      = 100
)

var ErrNotImplemented = fmt.Errorf("snyk: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	OrgID string `json:"org_id"`
}

type Secrets struct {
	APIToken string `json:"api_token"`
}

type SnykAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *SnykAccessConnector { return &SnykAccessConnector{} }
func init()                     { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("snyk: config is nil")
	}
	var cfg Config
	if v, ok := raw["org_id"].(string); ok {
		cfg.OrgID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("snyk: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_token"].(string); ok {
		s.APIToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.OrgID) == "" {
		return errors.New("snyk: org_id is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIToken) == "" {
		return errors.New("snyk: api_token is required")
	}
	return nil
}

func (c *SnykAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *SnykAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *SnykAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *SnykAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.api+json")
	req.Header.Set("Authorization", "token "+strings.TrimSpace(secrets.APIToken))
	return req, nil
}

func (c *SnykAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("snyk: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("snyk: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *SnykAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *SnykAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := fmt.Sprintf("%s/rest/orgs/%s?version=%s", c.baseURL(), cfg.OrgID, apiVersion)
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("snyk: connect probe: %w", err)
	}
	return nil
}

func (c *SnykAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type snykMembersResponse struct {
	Data  []snykMember `json:"data"`
	Links struct {
		Next string `json:"next,omitempty"`
	} `json:"links"`
}

type snykMember struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Role     string `json:"role"`
		Username string `json:"username"`
	} `json:"attributes"`
}

func (c *SnykAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *SnykAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	nextURL := checkpoint
	if nextURL == "" {
		nextURL = fmt.Sprintf("%s/rest/orgs/%s/members?version=%s&limit=%d",
			c.baseURL(), cfg.OrgID, apiVersion, pageLimit)
	} else if c.urlOverride != "" && strings.HasPrefix(nextURL, "/") {
		nextURL = c.baseURL() + nextURL
	}
	for {
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp snykMembersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("snyk: decode members: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Data))
		for _, m := range resp.Data {
			display := m.Attributes.Name
			if display == "" {
				display = m.Attributes.Username
			}
			if display == "" {
				display = m.Attributes.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  m.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       m.Attributes.Email,
				Status:      "active",
			})
		}
		next := resp.Links.Next
		if next != "" {
			next = rewriteSnykNext(next, c.baseURL())
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		nextURL = next
	}
}

// rewriteSnykNext converts a relative `links.next` into an absolute URL using
// the connector's effective base URL.
func rewriteSnykNext(next, base string) string {
	if next == "" {
		return ""
	}
	if strings.HasPrefix(next, "http://") || strings.HasPrefix(next, "https://") {
		return next
	}
	u, err := url.Parse(next)
	if err != nil {
		return next
	}
	return strings.TrimRight(base, "/") + u.RequestURI()
}

func (c *SnykAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("snyk: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	role := grant.Role
	if role == "" {
		role = "collaborator"
	}
	body, _ := json.Marshal(map[string]interface{}{"data": map[string]interface{}{"attributes": map[string]string{"role": role}, "type": "org-membership"}})
	urlStr := fmt.Sprintf("%s/rest/orgs/%s/members/%s?version=%s", c.baseURL(), url.PathEscape(cfg.OrgID), url.PathEscape(grant.UserExternalID), apiVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, urlStr, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/vnd.api+json")
	req.Header.Set("Authorization", "token "+strings.TrimSpace(secrets.APIToken))
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("snyk: provision: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("snyk: provision status %d: %s", resp.StatusCode, string(respBody))
}

func (c *SnykAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("snyk: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	urlStr := fmt.Sprintf("%s/rest/orgs/%s/members/%s?version=%s", c.baseURL(), url.PathEscape(cfg.OrgID), url.PathEscape(grant.UserExternalID), apiVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, urlStr, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "token "+strings.TrimSpace(secrets.APIToken))
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("snyk: revoke: %w", err)
	}
	defer resp.Body.Close()
	if (resp.StatusCode >= 200 && resp.StatusCode < 300) || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("snyk: revoke status %d: %s", resp.StatusCode, string(respBody))
}

func (c *SnykAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("snyk: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	urlStr := fmt.Sprintf("%s/rest/orgs/%s/members/%s?version=%s", c.baseURL(), url.PathEscape(cfg.OrgID), url.PathEscape(userExternalID), apiVersion)
	req, err := c.newRequest(ctx, secrets, http.MethodGet, urlStr)
	if err != nil {
		return nil, err
	}
	body, status, err := snykDoRaw(c, req)
	if err != nil {
		// Member-not-found is a soft signal: the user holds no
		// entitlements, so return an empty list per the contract.
		// Transient/server/network failures (5xx, timeouts) must
		// surface so the caller can retry instead of recording a
		// false "no access" during an upstream outage.
		if status == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	var resp struct {
		Data struct {
			Attributes struct {
				Role string `json:"role"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("snyk: decode entitlements: %w", err)
	}
	return []access.Entitlement{{ResourceExternalID: cfg.OrgID, Role: resp.Data.Attributes.Role, Source: "direct"}}, nil
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker Snyk SSO
// federation. When `sso_metadata_url` is blank the helper returns
// (nil, nil) and the caller gracefully downgrades.
func (c *SnykAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *SnykAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"org_id":      cfg.OrgID,
		"auth_type":   "api_token",
		"token_short": shortToken(secrets.APIToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*SnykAccessConnector)(nil)
