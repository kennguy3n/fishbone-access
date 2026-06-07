// Package gitlab implements the access.AccessConnector contract for the
// GitLab group members API.
package gitlab

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
	ProviderName   = "gitlab"
	defaultBaseURL = "https://gitlab.com"
)

var ErrNotImplemented = fmt.Errorf("gitlab: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	GroupID string `json:"group_id"`
	BaseURL string `json:"base_url,omitempty"`
}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type GitLabAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *GitLabAccessConnector { return &GitLabAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("gitlab: config is nil")
	}
	var cfg Config
	if v, ok := raw["group_id"].(string); ok {
		cfg.GroupID = v
	}
	if v, ok := raw["base_url"].(string); ok {
		cfg.BaseURL = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("gitlab: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_token"].(string); ok {
		s.AccessToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.GroupID) == "" {
		return errors.New("gitlab: group_id is required")
	}
	if c.BaseURL != "" && !strings.HasPrefix(c.BaseURL, "http://") && !strings.HasPrefix(c.BaseURL, "https://") {
		return errors.New("gitlab: base_url must include scheme")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("gitlab: access_token is required")
	}
	return nil
}

func (c *GitLabAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *GitLabAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	if cfg.BaseURL != "" {
		return strings.TrimRight(cfg.BaseURL, "/")
	}
	return defaultBaseURL
}

// sharedHTTPClient is reused across requests so the underlying
// http.Transport connection pool (keep-alives, TLS sessions) is shared
// rather than rebuilt on every call. http.Client is safe for concurrent
// use by multiple goroutines.
var sharedHTTPClient = &http.Client{Timeout: 30 * time.Second}

func (c *GitLabAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return sharedHTTPClient
}

func (c *GitLabAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

// rawResponse holds the status, header, and drained body of a GitLab
// response. doRaw closes the live *http.Response.Body inside the
// helper and returns this primitive snapshot so callers can read the
// pagination headers (X-Next-Page) and the StatusCode without needing
// to manage body lifetime. Returning the primitive instead of the
// live *http.Response also keeps bodyclose from misfiring on every
// caller — the linter cannot see through a helper that closes the
// body internally.
type rawResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func (c *GitLabAccessConnector) doRaw(req *http.Request) (*rawResponse, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("gitlab: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	r := &rawResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       body,
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return r, fmt.Errorf("gitlab: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return r, nil
}

func (c *GitLabAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *GitLabAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.baseURL(cfg)+"/api/v4/groups/"+url.PathEscape(cfg.GroupID))
	if err != nil {
		return err
	}
	if _, err := c.doRaw(req); err != nil {
		return fmt.Errorf("gitlab: connect probe: %w", err)
	}
	return nil
}

func (c *GitLabAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type gitlabMember struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email,omitempty"`
	State    string `json:"state"`
}

func (c *GitLabAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *GitLabAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	page := 1
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &page)
		if page < 1 {
			page = 1
		}
	}
	base := c.baseURL(cfg)
	for {
		path := fmt.Sprintf("%s/api/v4/groups/%s/members/all?per_page=100&page=%d", base, url.PathEscape(cfg.GroupID), page)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}
		var members []gitlabMember
		if err := json.Unmarshal(resp.Body, &members); err != nil {
			return fmt.Errorf("gitlab: decode members: %w", err)
		}
		identities := make([]*access.Identity, 0, len(members))
		for _, m := range members {
			status := "active"
			if m.State != "" && !strings.EqualFold(m.State, "active") {
				status = strings.ToLower(m.State)
			}
			display := m.Name
			if display == "" {
				display = m.Username
			}
			identities = append(identities, &access.Identity{
				ExternalID:  fmt.Sprintf("%d", m.ID),
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       m.Email,
				Status:      status,
			})
		}
		next := ""
		// GitLab's pagination uses X-Next-Page; if absent / empty, stop.
		if v := resp.Header.Get("X-Next-Page"); v != "" {
			next = v
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		page++
	}
}

// ProvisionAccess adds a user to a GitLab group. 409 = idempotent.
func (c *GitLabAccessConnector) ProvisionAccess(
	ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant,
) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("gitlab: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	accessLevel := 30 // developer default
	if grant.Role != "" {
		_, _ = fmt.Sscanf(grant.Role, "%d", &accessLevel)
	}
	body, _ := json.Marshal(map[string]interface{}{"user_id": grant.UserExternalID, "access_level": accessLevel})
	urlStr := fmt.Sprintf("%s/api/v4/groups/%s/members", c.baseURL(cfg), url.PathEscape(grant.ResourceExternalID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("gitlab: provision: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	// 201/200 = added, 409 = already a member (idempotent). Classify the
	// rest with the shared helpers so a 5xx/429 surfaces as a transient
	// error the worker will retry, matching the other connectors.
	switch {
	case resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK:
		return nil
	case access.IsIdempotentProvisionStatus(resp.StatusCode, respBody):
		return nil
	case access.IsTransientStatus(resp.StatusCode):
		return fmt.Errorf("gitlab: provision transient status %d: %s", resp.StatusCode, string(respBody))
	default:
		return fmt.Errorf("gitlab: provision status %d: %s", resp.StatusCode, string(respBody))
	}
}

// RevokeAccess removes a user from a GitLab group. 404 = idempotent.
func (c *GitLabAccessConnector) RevokeAccess(
	ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant,
) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("gitlab: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	urlStr := fmt.Sprintf("%s/api/v4/groups/%s/members/%s",
		c.baseURL(cfg), url.PathEscape(grant.ResourceExternalID), url.PathEscape(grant.UserExternalID))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, urlStr, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("gitlab: revoke: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	// 204/200 = removed, 404 = already absent (idempotent). Classify the
	// rest with the shared helpers so a 5xx/429 surfaces as a transient
	// error the worker will retry.
	switch {
	case resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK:
		return nil
	case access.IsIdempotentRevokeStatus(resp.StatusCode, respBody):
		return nil
	case access.IsTransientStatus(resp.StatusCode):
		return fmt.Errorf("gitlab: revoke transient status %d: %s", resp.StatusCode, string(respBody))
	default:
		return fmt.Errorf("gitlab: revoke status %d: %s", resp.StatusCode, string(respBody))
	}
}

// ListEntitlements returns the user's access level in a GitLab group.
func (c *GitLabAccessConnector) ListEntitlements(
	ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string,
) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("gitlab: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	urlStr := fmt.Sprintf("%s/api/v4/groups/%s/members/%s",
		c.baseURL(cfg), url.PathEscape(cfg.GroupID), url.PathEscape(userExternalID))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, urlStr)
	if err != nil {
		return nil, err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		// 404 means the user is not a member of the group — a soft signal
		// that maps cleanly to "no entitlements". Any other status (403,
		// 5xx, ...) or a transport error means we could not determine
		// membership, so surface it rather than masking a real failure as
		// an empty list.
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	var m struct {
		AccessLevel int    `json:"access_level"`
		Username    string `json:"username"`
	}
	if json.Unmarshal(resp.Body, &m) != nil {
		return nil, nil
	}
	return []access.Entitlement{{
		ResourceExternalID: cfg.GroupID,
		Role:               fmt.Sprintf("%d", m.AccessLevel),
		Source:             "direct",
	}}, nil
}

// GetSSOMetadata returns the GitLab group SAML SSO metadata URL. GitLab
// groups expose SAML metadata at `/groups/{group}/-/saml/metadata`.
func (c *GitLabAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	// The metadata/entity URLs are derived purely from config (the group
	// path / base URL); this method never calls the API. Decode and validate
	// only the config so an admin-UI preview that has the group but no secret
	// can still resolve the SSO URLs — requiring secrets here would be a
	// needless coupling that makes GetSSOMetadata(cfg, nil) fail.
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	base := defaultBaseURL
	if cfg.BaseURL != "" {
		base = strings.TrimRight(cfg.BaseURL, "/")
	}
	groupPath := url.PathEscape(cfg.GroupID)
	return &access.SSOMetadata{
		Protocol:    "saml",
		MetadataURL: fmt.Sprintf("%s/groups/%s/-/saml/metadata", base, groupPath),
		EntityID:    fmt.Sprintf("%s/groups/%s", base, groupPath),
	}, nil
}

func (c *GitLabAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{
		"provider":    ProviderName,
		"group_id":    cfg.GroupID,
		"auth_type":   "access_token",
		"token_short": shortToken(secrets.AccessToken),
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

var _ access.AccessConnector = (*GitLabAccessConnector)(nil)
