// Package zoom implements the access.AccessConnector contract for the Zoom
// Server-to-Server OAuth API.
package zoom

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
	"sync"
	"time"

	"bytes"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName   = "zoom"
	defaultBaseURL = "https://api.zoom.us/v2"
	// gosec G101 false positive: this is Zoom's documented public
	// OAuth token endpoint, not a hardcoded credential.
	defaultTokenURL = "https://zoom.us/oauth/token" // #nosec G101
)

var ErrNotImplemented = fmt.Errorf("zoom: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	AccountID string `json:"account_id"`
}

type Secrets struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// ZoomAccessConnector implements access.AccessConnector. The connector is
// safe for concurrent reuse — each call obtains a fresh server-to-server
// access token (with simple in-memory caching for the lifetime of the
// connector instance).
type ZoomAccessConnector struct {
	httpClient    func() httpDoer
	urlOverride   string
	tokenURLOver  string
	tokenOverride func(ctx context.Context, cfg Config, secrets Secrets) (string, error)

	tokenMu     sync.Mutex
	cachedToken string
	tokenExpiry time.Time
}

func New() *ZoomAccessConnector { return &ZoomAccessConnector{} }
func init()                     { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("zoom: config is nil")
	}
	var cfg Config
	if v, ok := raw["account_id"].(string); ok {
		cfg.AccountID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("zoom: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["client_id"].(string); ok {
		s.ClientID = v
	}
	if v, ok := raw["client_secret"].(string); ok {
		s.ClientSecret = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.AccountID) == "" {
		return errors.New("zoom: account_id is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.ClientID) == "" {
		return errors.New("zoom: client_id is required")
	}
	if strings.TrimSpace(s.ClientSecret) == "" {
		return errors.New("zoom: client_secret is required")
	}
	return nil
}

func (c *ZoomAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *ZoomAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *ZoomAccessConnector) tokenURL() string {
	if c.tokenURLOver != "" {
		return c.tokenURLOver
	}
	return defaultTokenURL
}

func (c *ZoomAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *ZoomAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *ZoomAccessConnector) accessToken(ctx context.Context, cfg Config, secrets Secrets) (string, error) {
	if c.tokenOverride != nil {
		return c.tokenOverride(ctx, cfg, secrets)
	}
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.cachedToken != "" && time.Now().Before(c.tokenExpiry.Add(-1*time.Minute)) {
		return c.cachedToken, nil
	}
	form := url.Values{}
	form.Set("grant_type", "account_credentials")
	form.Set("account_id", cfg.AccountID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	basic := base64.StdEncoding.EncodeToString([]byte(secrets.ClientID + ":" + secrets.ClientSecret))
	req.Header.Set("Authorization", "Basic "+basic)
	resp, err := c.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("zoom: token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("zoom: token: status %d: %s", resp.StatusCode, string(body))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("zoom: decode token: %w", err)
	}
	c.cachedToken = tok.AccessToken
	if tok.ExpiresIn > 0 {
		c.tokenExpiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	return c.cachedToken, nil
}

func (c *ZoomAccessConnector) newRequest(ctx context.Context, token, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return req, nil
}

func (c *ZoomAccessConnector) do(req *http.Request) ([]byte, error) {
	body, _, err := c.doWithStatus(req)
	return body, err
}

// doWithStatus is do() but exposes the upstream HTTP status code as a
// separate return value so callers (e.g. audit log fetch) can branch on
// the numeric code instead of string-matching on the formatted error
// message — which is fragile when an upstream 5xx body happens to embed
// text like "status 403". On non-2xx the body is still surfaced alongside
// the error so callers can pass through the upstream diagnostic.
func (c *ZoomAccessConnector) doWithStatus(req *http.Request) ([]byte, int, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("zoom: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return body, resp.StatusCode, fmt.Errorf("zoom: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, resp.StatusCode, nil
}

func (c *ZoomAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	tok, err := c.accessToken(ctx, cfg, secrets)
	if err != nil {
		return fmt.Errorf("zoom: connect: token: %w", err)
	}
	req, err := c.newRequest(ctx, tok, http.MethodGet, "/users?status=active&page_size=1")
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("zoom: connect probe: %w", err)
	}
	return nil
}

func (c *ZoomAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type zoomUsersResponse struct {
	PageCount     int        `json:"page_count"`
	PageNumber    int        `json:"page_number"`
	PageSize      int        `json:"page_size"`
	TotalRecords  int        `json:"total_records"`
	NextPageToken string     `json:"next_page_token,omitempty"`
	Users         []zoomUser `json:"users"`
}

type zoomUser struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Type      int    `json:"type"`
	Status    string `json:"status"`
}

func (c *ZoomAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	tok, err := c.accessToken(ctx, cfg, secrets)
	if err != nil {
		return 0, err
	}
	req, err := c.newRequest(ctx, tok, http.MethodGet, "/users?page_size=1&status=active")
	if err != nil {
		return 0, err
	}
	body, err := c.do(req)
	if err != nil {
		return 0, err
	}
	var resp zoomUsersResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, fmt.Errorf("zoom: decode users: %w", err)
	}
	return resp.TotalRecords, nil
}

func (c *ZoomAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	tok, err := c.accessToken(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	pageToken := checkpoint
	for {
		path := "/users?status=active&page_size=300"
		if pageToken != "" {
			path += "&next_page_token=" + url.QueryEscape(pageToken)
		}
		req, err := c.newRequest(ctx, tok, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp zoomUsersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("zoom: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Users))
		for _, u := range resp.Users {
			display := strings.TrimSpace(u.FirstName + " " + u.LastName)
			if display == "" {
				display = u.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      strings.ToLower(u.Status),
			})
		}
		if err := handler(identities, resp.NextPageToken); err != nil {
			return err
		}
		if resp.NextPageToken == "" {
			return nil
		}
		pageToken = resp.NextPageToken
	}
}

func (c *ZoomAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("zoom: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.accessToken(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"id": grant.UserExternalID})
	urlStr := fmt.Sprintf("%s/groups/%s/members", c.baseURL(), url.PathEscape(grant.ResourceExternalID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("zoom: provision: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode == http.StatusConflict || strings.Contains(string(respBody), "already exists") {
		return nil
	}
	return fmt.Errorf("zoom: provision status %d: %s", resp.StatusCode, string(respBody))
}

func (c *ZoomAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("zoom: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.accessToken(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	urlStr := fmt.Sprintf("%s/groups/%s/members/%s", c.baseURL(), url.PathEscape(grant.ResourceExternalID), url.PathEscape(grant.UserExternalID))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, urlStr, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("zoom: revoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("zoom: revoke status %d: %s", resp.StatusCode, string(respBody))
}

func (c *ZoomAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("zoom: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	token, err := c.accessToken(ctx, cfg, secrets)
	if err != nil {
		return nil, err
	}
	urlStr := fmt.Sprintf("%s/users/%s/groups", c.baseURL(), url.PathEscape(userExternalID))
	req, err := c.newRequest(ctx, token, http.MethodGet, urlStr[len(c.baseURL()):])
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Groups []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"groups"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return nil, nil
	}
	var out []access.Entitlement
	for _, g := range resp.Groups {
		out = append(out, access.Entitlement{ResourceExternalID: g.ID, Role: "member", Source: "direct"})
	}
	return out, nil
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker Zoom SSO
// federation. When `sso_metadata_url` is blank the helper returns
// (nil, nil) and the caller gracefully downgrades.
func (c *ZoomAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *ZoomAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":        ProviderName,
		"account_id":      cfg.AccountID,
		"auth_type":       "server_to_server_oauth",
		"client_id_short": shortToken(secrets.ClientID),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*ZoomAccessConnector)(nil)
