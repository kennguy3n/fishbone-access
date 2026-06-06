// Package pagerduty implements the access.AccessConnector contract for the
// PagerDuty users API.
package pagerduty

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
	"github.com/kennguy3n/fishbone-access/internal/services/access/httputil"
)

const (
	ProviderName   = "pagerduty"
	defaultBaseURL = "https://api.pagerduty.com"
	pageLimit      = 100
)

var ErrNotImplemented = fmt.Errorf("pagerduty: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	APIToken string `json:"api_token"`
}

type PagerDutyAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *PagerDutyAccessConnector { return &PagerDutyAccessConnector{} }
func init()                          { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(_ map[string]interface{}) (Config, error) { return Config{}, nil }

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("pagerduty: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_token"].(string); ok {
		s.APIToken = v
	}
	return s, nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIToken) == "" {
		return errors.New("pagerduty: api_token is required")
	}
	return nil
}

func (c *PagerDutyAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
	if _, err := DecodeConfig(configRaw); err != nil {
		return err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return err
	}
	return s.validate()
}

func (c *PagerDutyAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

// doHTTP routes the request through the injected test httpClient when
// present, otherwise through the shared RetryClient so production
// traffic reuses the connection pool (keep-alive, TLS sessions) and
// gets the 429/5xx retry-with-jitter policy.
func (c *PagerDutyAccessConnector) doHTTP(req *http.Request) (*http.Response, error) {
	if c.httpClient != nil {
		return c.httpClient().Do(req)
	}
	return sharedRetryClient.Do(req.Context(), req)
}

// sharedRetryClient is a package-level singleton so the underlying
// *http.Client connection pool is reused across requests rather than
// rebuilt per call.
var sharedRetryClient = httputil.NewRetryClient(30 * time.Second)

func (c *PagerDutyAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, path string) (*http.Request, error) {
	return c.newRequestBody(ctx, secrets, method, path, nil)
}

// newRequestBody builds a PagerDuty API request with the standard Accept
// and Authorization headers. All mutating endpoints (ProvisionAccess,
// RevokeAccess) MUST go through this helper so the required
// Accept: application/vnd.pagerduty+json;version=2 header is never dropped.
func (c *PagerDutyAccessConnector) newRequestBody(ctx context.Context, secrets Secrets, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.pagerduty+json;version=2")
	req.Header.Set("Authorization", "Token token="+strings.TrimSpace(secrets.APIToken))
	return req, nil
}

func (c *PagerDutyAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.doHTTP(req)
	if err != nil {
		return nil, fmt.Errorf("pagerduty: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("pagerduty: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *PagerDutyAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *PagerDutyAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/users?limit=1")
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("pagerduty: connect probe: %w", err)
	}
	return nil
}

func (c *PagerDutyAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type pagerdutyUsersResponse struct {
	Users  []pagerdutyUser `json:"users"`
	Limit  int             `json:"limit"`
	Offset int             `json:"offset"`
	More   bool            `json:"more"`
	Total  *int            `json:"total,omitempty"`
}

type pagerdutyUser struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
	Type  string `json:"type"`
}

func (c *PagerDutyAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *PagerDutyAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
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
	for {
		path := fmt.Sprintf("/users?limit=%d&offset=%d", pageLimit, offset)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp pagerdutyUsersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("pagerduty: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Users))
		for _, u := range resp.Users {
			display := u.Name
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
		next := ""
		if resp.More {
			next = fmt.Sprintf("%d", offset+len(resp.Users))
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset += len(resp.Users)
	}
}

func (c *PagerDutyAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("pagerduty: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	role := grant.Role
	if role == "" {
		role = "responder"
	}
	body, _ := json.Marshal(map[string]string{"role": role})
	path := fmt.Sprintf("/teams/%s/users/%s", url.PathEscape(grant.ResourceExternalID), url.PathEscape(grant.UserExternalID))
	req, err := c.newRequestBody(ctx, secrets, http.MethodPut, path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.doHTTP(req)
	if err != nil {
		return fmt.Errorf("pagerduty: provision: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("pagerduty: provision status %d: %s", resp.StatusCode, string(respBody))
}

func (c *PagerDutyAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("pagerduty: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/teams/%s/users/%s", url.PathEscape(grant.ResourceExternalID), url.PathEscape(grant.UserExternalID))
	req, err := c.newRequestBody(ctx, secrets, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	resp, err := c.doHTTP(req)
	if err != nil {
		return fmt.Errorf("pagerduty: revoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("pagerduty: revoke status %d: %s", resp.StatusCode, string(respBody))
}

func (c *PagerDutyAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("pagerduty: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/users/%s?include%%5B%%5D=teams", url.PathEscape(userExternalID))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var resp struct {
		User struct {
			Teams []struct {
				ID   string `json:"id"`
				Role string `json:"role"`
			} `json:"teams"`
		} `json:"user"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return nil, nil
	}
	var out []access.Entitlement
	for _, t := range resp.User.Teams {
		out = append(out, access.Entitlement{ResourceExternalID: t.ID, Role: t.Role, Source: "direct"})
	}
	return out, nil
}

// GetSSOMetadata returns the operator-supplied SAML metadata URL if
// configured. PagerDuty federates SSO via SAML 2.0 from the account
// SSO settings; when `sso_metadata_url` is blank the helper returns
// (nil, nil) and the caller gracefully downgrades.
func (c *PagerDutyAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *PagerDutyAccessConnector) GetCredentialsMetadata(_ context.Context, _, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "api_token",
		"token_short": shortToken(s.APIToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*PagerDutyAccessConnector)(nil)
