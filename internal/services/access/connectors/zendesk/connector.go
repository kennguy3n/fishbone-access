// Package zendesk implements the access.AccessConnector contract for the
// Zendesk users API.
package zendesk

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"bytes"

	"net/url"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName = "zendesk"
)

var ErrNotImplemented = fmt.Errorf("zendesk: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Subdomain string `json:"subdomain"`
}

type Secrets struct {
	APIToken string `json:"api_token"`
	Email    string `json:"email"`
}

type ZendeskAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *ZendeskAccessConnector { return &ZendeskAccessConnector{} }
func init()                        { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("zendesk: config is nil")
	}
	var cfg Config
	if v, ok := raw["subdomain"].(string); ok {
		cfg.Subdomain = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("zendesk: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_token"].(string); ok {
		s.APIToken = v
	}
	if v, ok := raw["email"].(string); ok {
		s.Email = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.Subdomain) == "" {
		return errors.New("zendesk: subdomain is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIToken) == "" {
		return errors.New("zendesk: api_token is required")
	}
	if strings.TrimSpace(s.Email) == "" {
		return errors.New("zendesk: email is required")
	}
	return nil
}

func (c *ZendeskAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *ZendeskAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://" + cfg.Subdomain + ".zendesk.com"
}

func (c *ZendeskAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func basicAuthHeader(email, token string) string {
	creds := strings.TrimSpace(email) + "/token:" + strings.TrimSpace(token)
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
}

func (c *ZendeskAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", basicAuthHeader(secrets.Email, secrets.APIToken))
	return req, nil
}

func (c *ZendeskAccessConnector) do(req *http.Request) ([]byte, error) {
	body, _, err := c.doWithStatus(req)
	return body, err
}

// doWithStatus is do() but exposes the upstream HTTP status code as a
// separate return value so callers (delta sync, audit log fetch) can
// branch on the numeric code without string-matching on the formatted
// error message — which is fragile when an upstream 5xx body happens
// to embed text like "status 403". On non-2xx the returned body is
// still surfaced (alongside an error) so callers can pass through the
// upstream diagnostic when they choose to.
func (c *ZendeskAccessConnector) doWithStatus(req *http.Request) ([]byte, int, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("zendesk: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return body, resp.StatusCode, fmt.Errorf("zendesk: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, resp.StatusCode, nil
}

func (c *ZendeskAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *ZendeskAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL(cfg) + "/api/v2/users/me.json"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("zendesk: connect probe: %w", err)
	}
	return nil
}

func (c *ZendeskAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type zendeskUsersResponse struct {
	Users    []zendeskUser `json:"users"`
	NextPage string        `json:"next_page,omitempty"`
}

type zendeskUser struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	Active    bool   `json:"active"`
	Suspended bool   `json:"suspended"`
}

func (c *ZendeskAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *ZendeskAccessConnector) SyncIdentities(
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
		nextURL = c.baseURL(cfg) + "/api/v2/users.json?per_page=100"
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
		var resp zendeskUsersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("zendesk: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Users))
		for _, u := range resp.Users {
			status := "active"
			switch {
			case u.Suspended:
				status = "suspended"
			case !u.Active:
				status = "inactive"
			}
			display := u.Name
			if display == "" {
				display = u.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  fmt.Sprintf("%d", u.ID),
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      status,
			})
		}
		next := resp.NextPage
		// rewrite next_page URL if it points at the real Zendesk domain
		// when running against a test override server.
		if next != "" && c.urlOverride != "" {
			next = strings.Replace(next, "https://"+cfg.Subdomain+".zendesk.com", strings.TrimRight(c.urlOverride, "/"), 1)
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

func (c *ZendeskAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("zendesk: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]interface{}{"group_membership": map[string]interface{}{"user_id": grant.UserExternalID, "group_id": grant.ResourceExternalID}})
	urlStr := fmt.Sprintf("%s/api/v2/group_memberships.json", c.baseURL(cfg))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(secrets.Email+"/token", secrets.APIToken)
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("zendesk: provision: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		return nil
	}
	if strings.Contains(string(respBody), "already exists") || strings.Contains(string(respBody), "DuplicateValue") {
		return nil
	}
	return fmt.Errorf("zendesk: provision status %d: %s", resp.StatusCode, string(respBody))
}

func (c *ZendeskAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("zendesk: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	urlStr := fmt.Sprintf("%s/api/v2/group_memberships/%s.json", c.baseURL(cfg), url.PathEscape(grant.ResourceExternalID))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, urlStr, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(secrets.Email+"/token", secrets.APIToken)
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("zendesk: revoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("zendesk: revoke status %d: %s", resp.StatusCode, string(respBody))
}

func (c *ZendeskAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("zendesk: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	urlStr := fmt.Sprintf("%s/api/v2/users/%s/group_memberships.json", c.baseURL(cfg), url.PathEscape(userExternalID))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, urlStr)
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var resp struct {
		GroupMemberships []struct {
			GroupID int `json:"group_id"`
		} `json:"group_memberships"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		// Propagate decode failures rather than reporting "no
		// entitlements": a 2xx body that does not parse (e.g. an HTML
		// error page from a misconfigured proxy, or a truncated
		// payload) means the truth is unknown, not that the user lacks
		// access. Swallowing it would risk an incorrect access decision.
		return nil, fmt.Errorf("zendesk: decode group memberships: %w", err)
	}
	var out []access.Entitlement
	for _, gm := range resp.GroupMemberships {
		out = append(out, access.Entitlement{ResourceExternalID: fmt.Sprintf("%d", gm.GroupID), Role: "member", Source: "direct"})
	}
	return out, nil
}

// GetSSOMetadata returns the Zendesk SAML metadata URL for the configured
// subdomain. Zendesk publishes SAML metadata at
// `https://{subdomain}.zendesk.com/access/saml/metadata` once SSO is configured.
func (c *ZendeskAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	// SSO metadata is derived purely from the subdomain config, so only
	// decode/validate the config. Requiring secrets here (as decodeBoth
	// did) breaks the interface contract and fails when metadata is
	// queried before credentials are provisioned; every other connector
	// ignores secrets in GetSSOMetadata.
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	host := "https://" + cfg.Subdomain + ".zendesk.com"
	return &access.SSOMetadata{
		Protocol:    "saml",
		MetadataURL: host + "/access/saml/metadata",
		EntityID:    host,
	}, nil
}

func (c *ZendeskAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"subdomain":   cfg.Subdomain,
		"email":       secrets.Email,
		"auth_type":   "basic_token",
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

var _ access.AccessConnector = (*ZendeskAccessConnector)(nil)
