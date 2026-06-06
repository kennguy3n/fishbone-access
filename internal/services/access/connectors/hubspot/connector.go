// Package hubspot implements the access.AccessConnector contract for the
// HubSpot account users API.
package hubspot

import (
	"context"
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
	ProviderName   = "hubspot"
	defaultBaseURL = "https://api.hubapi.com"
)

var ErrNotImplemented = fmt.Errorf("hubspot: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type HubSpotAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *HubSpotAccessConnector { return &HubSpotAccessConnector{} }
func init()                        { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(_ map[string]interface{}) (Config, error) { return Config{}, nil }

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("hubspot: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_token"].(string); ok {
		s.AccessToken = v
	}
	return s, nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("hubspot: access_token is required")
	}
	return nil
}

func (c *HubSpotAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
	if _, err := DecodeConfig(configRaw); err != nil {
		return err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return err
	}
	return s.validate()
}

func (c *HubSpotAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *HubSpotAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *HubSpotAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *HubSpotAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("hubspot: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("hubspot: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

// doRaw issues the request and returns the raw response so callers can
// branch on the exact status code (e.g. mapping 401/403/404 to
// access.ErrAuditNotAvailable) instead of string-matching c.do's error.
// The caller owns closing resp.Body.
func (c *HubSpotAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("hubspot: %s %s: %w", req.Method, req.URL.Path, err)
	}
	return resp, nil
}

func (c *HubSpotAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
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

func (c *HubSpotAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/settings/v3/users?limit=1")
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("hubspot: connect probe: %w", err)
	}
	return nil
}

func (c *HubSpotAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type hubspotUsersResponse struct {
	Results []hubspotUser `json:"results"`
	Paging  struct {
		Next struct {
			Link  string `json:"link,omitempty"`
			After string `json:"after,omitempty"`
		} `json:"next"`
	} `json:"paging"`
}

type hubspotUser struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
}

func (c *HubSpotAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *HubSpotAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	after := checkpoint
	for {
		q := url.Values{}
		q.Set("limit", "100")
		if after != "" {
			q.Set("after", after)
		}
		path := "/settings/v3/users?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp hubspotUsersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("hubspot: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Results))
		for _, u := range resp.Results {
			display := strings.TrimSpace(u.FirstName + " " + u.LastName)
			if display == "" {
				display = u.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      "active",
			})
		}
		next := resp.Paging.Next.After
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		after = next
	}
}

func (c *HubSpotAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if strings.TrimSpace(grant.UserExternalID) == "" || strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("hubspot: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]interface{}{"roleId": grant.ResourceExternalID})
	urlStr := fmt.Sprintf("%s/settings/v3/users/%s/roles", c.baseURL(), url.PathEscape(grant.UserExternalID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, urlStr, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("hubspot: provision: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case access.IsIdempotentProvisionStatus(resp.StatusCode, respBody):
		return nil
	case access.IsTransientStatus(resp.StatusCode):
		return fmt.Errorf("hubspot: provision transient status %d: %s", resp.StatusCode, string(respBody))
	default:
		return fmt.Errorf("hubspot: provision status %d: %s", resp.StatusCode, string(respBody))
	}
}

func (c *HubSpotAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if strings.TrimSpace(grant.UserExternalID) == "" || strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("hubspot: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	urlStr := fmt.Sprintf("%s/settings/v3/users/%s/roles/%s", c.baseURL(), url.PathEscape(grant.UserExternalID), url.PathEscape(grant.ResourceExternalID))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, urlStr, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("hubspot: revoke: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case access.IsIdempotentRevokeStatus(resp.StatusCode, respBody):
		return nil
	case access.IsTransientStatus(resp.StatusCode):
		return fmt.Errorf("hubspot: revoke transient status %d: %s", resp.StatusCode, string(respBody))
	default:
		return fmt.Errorf("hubspot: revoke status %d: %s", resp.StatusCode, string(respBody))
	}
}

func (c *HubSpotAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	if strings.TrimSpace(userExternalID) == "" {
		return nil, errors.New("hubspot: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/settings/v3/users/%s", url.PathEscape(userExternalID))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
	if err != nil {
		return nil, err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	// A user with no roles (or a deleted user) returns 404; surface that
	// as an empty entitlement list rather than a hard error, matching the
	// other connectors in this batch (e.g. heroku/advanced.go).
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("hubspot: list entitlements status %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		RoleIds []string `json:"roleIds"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("hubspot: decode entitlements: %w", err)
	}
	var out []access.Entitlement
	for _, r := range payload.RoleIds {
		out = append(out, access.Entitlement{ResourceExternalID: r, Role: r, Source: "direct"})
	}
	return out, nil
}

// GetSSOMetadata returns the operator-supplied SAML metadata URL if
// configured. HubSpot federates SSO via SAML 2.0 with metadata hosted
// by the customer's IdP; when `sso_metadata_url` is blank the helper
// returns (nil, nil) and the caller gracefully downgrades.
func (c *HubSpotAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *HubSpotAccessConnector) GetCredentialsMetadata(_ context.Context, _, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "access_token",
		"token_short": shortToken(s.AccessToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return strings.Repeat("*", len(t))
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*HubSpotAccessConnector)(nil)
