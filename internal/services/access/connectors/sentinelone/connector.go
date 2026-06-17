// Package sentinelone implements the access.AccessConnector contract for the
// SentinelOne console users API.
package sentinelone

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
	ProviderName = "sentinelone"
	pageLimit    = 100
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	ManagementURL string `json:"management_url"`
}

type Secrets struct {
	APIToken string `json:"api_token"`
}

type SentinelOneAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *SentinelOneAccessConnector { return &SentinelOneAccessConnector{} }
func init()                            { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("sentinelone: config is nil")
	}
	var cfg Config
	if v, ok := raw["management_url"].(string); ok {
		cfg.ManagementURL = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("sentinelone: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_token"].(string); ok {
		s.APIToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	mu := strings.TrimSpace(c.ManagementURL)
	if mu == "" {
		return errors.New("sentinelone: management_url is required")
	}
	if !strings.HasPrefix(mu, "http://") && !strings.HasPrefix(mu, "https://") {
		return errors.New("sentinelone: management_url must include scheme")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIToken) == "" {
		return errors.New("sentinelone: api_token is required")
	}
	return nil
}

func (c *SentinelOneAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *SentinelOneAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return strings.TrimRight(cfg.ManagementURL, "/")
}

func (c *SentinelOneAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *SentinelOneAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "ApiToken "+strings.TrimSpace(secrets.APIToken))
	return req, nil
}

func (c *SentinelOneAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "ApiToken "+strings.TrimSpace(secrets.APIToken))
	return req, nil
}

func (c *SentinelOneAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("sentinelone: %s %s: %w", req.Method, req.URL.Path, err)
	}
	return resp, nil
}

func (c *SentinelOneAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("sentinelone: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("sentinelone: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *SentinelOneAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *SentinelOneAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL(cfg) + "/web/api/v2.1/users?limit=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("sentinelone: connect probe: %w", err)
	}
	return nil
}

func (c *SentinelOneAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type sentineloneUsersResponse struct {
	Data       []sentineloneUser `json:"data"`
	Pagination struct {
		NextCursor *string `json:"nextCursor"`
		TotalItems int     `json:"totalItems"`
	} `json:"pagination"`
}

type sentineloneUser struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	FullName string `json:"fullName"`
	Role     string `json:"role"`
	IsActive *bool  `json:"isActive,omitempty"`
}

func (c *SentinelOneAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *SentinelOneAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	cursor := checkpoint
	base := c.baseURL(cfg)
	for {
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", pageLimit))
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		path := fmt.Sprintf("%s/web/api/v2.1/users?%s", base, q.Encode())
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp sentineloneUsersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("sentinelone: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Data))
		for _, u := range resp.Data {
			status := "active"
			if u.IsActive != nil && !*u.IsActive {
				status = "inactive"
			}
			display := u.FullName
			if display == "" {
				display = u.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      status,
			})
		}
		next := ""
		if resp.Pagination.NextCursor != nil && *resp.Pagination.NextCursor != "" {
			next = *resp.Pagination.NextCursor
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}

// ---------- advanced capabilities ----------

type sentineloneUserScope struct {
	Scope   string `json:"scope"`
	ScopeID string `json:"scopeId,omitempty"`
	Role    string `json:"role"`
}

type sentineloneUserDetailEnvelope struct {
	Data sentineloneUserDetail `json:"data"`
}

type sentineloneUserDetail struct {
	ID     string                 `json:"id"`
	Email  string                 `json:"email"`
	Role   string                 `json:"role,omitempty"`
	Scopes []sentineloneUserScope `json:"scopes,omitempty"`
}

func sentineloneRoleName(role string) string {
	role = strings.TrimSpace(role)
	if role == "" {
		return "Viewer"
	}
	return role
}

// ProvisionAccess assigns a role for the user via
// PUT /web/api/v2.1/users/{userId}. ResourceExternalID encodes the scope
// id (site/account). If the user already holds the same role for the
// same scope it is a no-op (idempotent success).
func (c *SentinelOneAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("sentinelone: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("sentinelone: grant.ResourceExternalID is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	role := sentineloneRoleName(grant.Role)
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"scopes": []map[string]interface{}{{
				"scope":   "site",
				"scopeId": grant.ResourceExternalID,
				"role":    role,
			}},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("sentinelone: marshal payload: %w", err)
	}
	fullURL := c.baseURL(cfg) + "/web/api/v2.1/users/" + url.PathEscape(grant.UserExternalID)
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPut, fullURL, body)
	if err != nil {
		return err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusConflict:
		return nil
	case resp.StatusCode == http.StatusBadRequest && bytes.Contains(bytes.ToLower(respBody), []byte("already")):
		return nil
	default:
		return fmt.Errorf("sentinelone: user PUT status %d: %s", resp.StatusCode, string(respBody))
	}
}

// RevokeAccess removes a role for the user via
// PUT /web/api/v2.1/users/{userId} with the scope filtered out.
// Missing user (404) maps to idempotent success.
func (c *SentinelOneAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("sentinelone: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("sentinelone: grant.ResourceExternalID is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"removeScopes": []map[string]interface{}{{
				"scopeId": grant.ResourceExternalID,
			}},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("sentinelone: marshal payload: %w", err)
	}
	fullURL := c.baseURL(cfg) + "/web/api/v2.1/users/" + url.PathEscape(grant.UserExternalID)
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPut, fullURL, body)
	if err != nil {
		return err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusNotFound:
		return nil
	default:
		return fmt.Errorf("sentinelone: user PUT status %d: %s", resp.StatusCode, string(respBody))
	}
}

// ListEntitlements reads /web/api/v2.1/users/{userId} and emits one
// Entitlement per scope assignment.
func (c *SentinelOneAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return nil, errors.New("sentinelone: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	fullURL := c.baseURL(cfg) + "/web/api/v2.1/users/" + url.PathEscape(userExternalID)
	req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
	if err != nil {
		return nil, err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		// Drain the (small) body so the connection can be reused by
		// the pool before we discard the response.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("sentinelone: user GET status %d: %s", resp.StatusCode, string(body))
	}
	var envelope sentineloneUserDetailEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("sentinelone: decode user: %w", err)
	}
	out := make([]access.Entitlement, 0, len(envelope.Data.Scopes))
	for _, sc := range envelope.Data.Scopes {
		out = append(out, access.Entitlement{
			ResourceExternalID: sc.ScopeID,
			Role:               sc.Role,
			Source:             "direct",
		})
	}
	return out, nil
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker SentinelOne
// management-console SSO federation. When `sso_metadata_url` is blank
// the helper returns (nil, nil) and the caller gracefully downgrades.
func (c *SentinelOneAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *SentinelOneAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":       ProviderName,
		"management_url": cfg.ManagementURL,
		"auth_type":      "api_token",
		"token_short":    shortToken(secrets.APIToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*SentinelOneAccessConnector)(nil)
