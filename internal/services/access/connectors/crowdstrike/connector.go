// Package crowdstrike implements the access.AccessConnector contract for the
// CrowdStrike user-management API.
//
// Auth flow: OAuth2 client_credentials at /oauth2/token using client_id +
// client_secret, returning a short-lived bearer token that is then used
// against the user-management endpoints.
//
// Identity sync uses the Falcon "query then hydrate" pattern:
//  1. GET /user-management/queries/users/v1?offset=N&limit=M  →  resources: ["uuid1", ...]
//  2. POST /user-management/entities/users/GET/v1 with {"ids":[...]} → user records.
package crowdstrike

import (
	"bytes"
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
	ProviderName   = "crowdstrike"
	defaultBaseURL = "https://api.crowdstrike.com"
	pageLimit      = 200
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	BaseURL string `json:"base_url,omitempty"`
}

type Secrets struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type CrowdStrikeAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *CrowdStrikeAccessConnector { return &CrowdStrikeAccessConnector{} }
func init()                            { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("crowdstrike: config is nil")
	}
	var cfg Config
	if v, ok := raw["base_url"].(string); ok {
		cfg.BaseURL = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("crowdstrike: secrets is nil")
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
	if c.BaseURL != "" && !strings.HasPrefix(c.BaseURL, "http://") && !strings.HasPrefix(c.BaseURL, "https://") {
		return errors.New("crowdstrike: base_url must include scheme")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.ClientID) == "" {
		return errors.New("crowdstrike: client_id is required")
	}
	if strings.TrimSpace(s.ClientSecret) == "" {
		return errors.New("crowdstrike: client_secret is required")
	}
	return nil
}

func (c *CrowdStrikeAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *CrowdStrikeAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	if cfg.BaseURL != "" {
		return strings.TrimRight(cfg.BaseURL, "/")
	}
	return defaultBaseURL
}

func (c *CrowdStrikeAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *CrowdStrikeAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func (c *CrowdStrikeAccessConnector) fetchToken(ctx context.Context, cfg Config, secrets Secrets) (string, error) {
	form := url.Values{}
	form.Set("client_id", strings.TrimSpace(secrets.ClientID))
	form.Set("client_secret", strings.TrimSpace(secrets.ClientSecret))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL(cfg)+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("crowdstrike: oauth2 token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("crowdstrike: oauth2 token: status %d: %s", resp.StatusCode, string(body))
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("crowdstrike: decode token: %w", err)
	}
	if tr.AccessToken == "" {
		return "", errors.New("crowdstrike: empty access_token")
	}
	return tr.AccessToken, nil
}

func (c *CrowdStrikeAccessConnector) authedDo(ctx context.Context, token, method, fullURL string, body io.Reader, contentType string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("crowdstrike: %s %s: %w", method, fullURL, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("crowdstrike: %s: status %d: %s", method, resp.StatusCode, string(rb))
	}
	return rb, nil
}

func (c *CrowdStrikeAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if _, err := c.fetchToken(ctx, cfg, secrets); err != nil {
		return fmt.Errorf("crowdstrike: connect probe: %w", err)
	}
	return nil
}

func (c *CrowdStrikeAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type queryUsersResponse struct {
	Resources []string `json:"resources"`
	Meta      struct {
		Pagination struct {
			Offset int `json:"offset"`
			Limit  int `json:"limit"`
			Total  int `json:"total"`
		} `json:"pagination"`
	} `json:"meta"`
	Errors []map[string]interface{} `json:"errors"`
}

type entityUsersResponse struct {
	Resources []crowdstrikeUser        `json:"resources"`
	Errors    []map[string]interface{} `json:"errors"`
}

type crowdstrikeUser struct {
	UUID      string `json:"uuid"`
	UID       string `json:"uid"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Status    string `json:"status,omitempty"`
}

func (c *CrowdStrikeAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *CrowdStrikeAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.fetchToken(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	base := c.baseURL(cfg)
	offset := 0
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &offset)
		if offset < 0 {
			offset = 0
		}
	}
	for {
		queryURL := fmt.Sprintf("%s/user-management/queries/users/v1?offset=%d&limit=%d", base, offset, pageLimit)
		qb, err := c.authedDo(ctx, token, http.MethodGet, queryURL, nil, "")
		if err != nil {
			return err
		}
		var qr queryUsersResponse
		if err := json.Unmarshal(qb, &qr); err != nil {
			return fmt.Errorf("crowdstrike: decode queries: %w", err)
		}
		identities := make([]*access.Identity, 0, len(qr.Resources))
		if len(qr.Resources) > 0 {
			payload, err := json.Marshal(map[string]interface{}{"ids": qr.Resources})
			if err != nil {
				return err
			}
			eb, err := c.authedDo(ctx, token, http.MethodPost,
				base+"/user-management/entities/users/GET/v1",
				bytes.NewReader(payload), "application/json")
			if err != nil {
				return err
			}
			var er entityUsersResponse
			if err := json.Unmarshal(eb, &er); err != nil {
				return fmt.Errorf("crowdstrike: decode entities: %w", err)
			}
			for _, u := range er.Resources {
				status := "active"
				if u.Status != "" && !strings.EqualFold(u.Status, "active") {
					status = strings.ToLower(u.Status)
				}
				display := strings.TrimSpace(u.FirstName + " " + u.LastName)
				if display == "" {
					display = u.UID
				}
				identities = append(identities, &access.Identity{
					ExternalID:  u.UUID,
					Type:        access.IdentityTypeUser,
					DisplayName: display,
					Email:       u.UID,
					Status:      status,
				})
			}
		}
		next := ""
		consumed := offset + len(qr.Resources)
		if consumed < qr.Meta.Pagination.Total && len(qr.Resources) > 0 {
			next = fmt.Sprintf("%d", consumed)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset = consumed
	}
}

func (c *CrowdStrikeAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("crowdstrike: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.fetchToken(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]interface{}{"action": "grant", "role_ids": []string{grant.ResourceExternalID}, "uuid": grant.UserExternalID})
	urlStr := c.baseURL(cfg) + "/user-management/entities/user-role-actions/v1"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("crowdstrike: provision: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if strings.Contains(string(respBody), "already") {
		return nil
	}
	return fmt.Errorf("crowdstrike: provision status %d: %s", resp.StatusCode, string(respBody))
}

func (c *CrowdStrikeAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("crowdstrike: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.fetchToken(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]interface{}{"action": "revoke", "role_ids": []string{grant.ResourceExternalID}, "uuid": grant.UserExternalID})
	urlStr := c.baseURL(cfg) + "/user-management/entities/user-role-actions/v1"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("crowdstrike: revoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if strings.Contains(string(respBody), "already") {
		return nil
	}
	return fmt.Errorf("crowdstrike: revoke status %d: %s", resp.StatusCode, string(respBody))
}

func (c *CrowdStrikeAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("crowdstrike: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	token, err := c.fetchToken(ctx, cfg, secrets)
	if err != nil {
		return nil, err
	}
	urlStr := fmt.Sprintf("%s/user-management/queries/roles/v1?user_uuid=%s", c.baseURL(cfg), url.QueryEscape(userExternalID))
	body, err := c.authedDo(ctx, token, http.MethodGet, urlStr, nil, "")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Resources []string `json:"resources"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("crowdstrike: decode entitlements: %w", err)
	}
	var out []access.Entitlement
	for _, r := range resp.Resources {
		out = append(out, access.Entitlement{ResourceExternalID: r, Role: r, Source: "direct"})
	}
	return out, nil
}
func (c *CrowdStrikeAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *CrowdStrikeAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{
		"provider":            ProviderName,
		"auth_type":           "oauth2_client_credentials",
		"client_id_short":     shortToken(secrets.ClientID),
		"client_secret_short": shortToken(secrets.ClientSecret),
	}
	if cfg.BaseURL != "" {
		out["base_url"] = cfg.BaseURL
	}
	return out, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*CrowdStrikeAccessConnector)(nil)
