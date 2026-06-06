// Package github implements the access.AccessConnector contract for the
// GitHub organization members API.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName   = "github"
	defaultBaseURL = "https://api.github.com"
)

var ErrNotImplemented = fmt.Errorf("github: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Organization string `json:"organization"`
}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type GitHubAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *GitHubAccessConnector { return &GitHubAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("github: config is nil")
	}
	var cfg Config
	if v, ok := raw["organization"].(string); ok {
		cfg.Organization = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("github: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_token"].(string); ok {
		s.AccessToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.Organization) == "" {
		return errors.New("github: organization is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("github: access_token is required")
	}
	return nil
}

func (c *GitHubAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *GitHubAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *GitHubAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *GitHubAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

// rawResponse holds the status, header, and drained body of an HTTP
// response. doRaw closes the live *http.Response.Body inside the
// helper and returns this primitive snapshot so callers can read the
// Link header (for pagination) and the StatusCode (for idempotency
// branches) without needing to manage body lifetime. Returning the
// primitive instead of the live *http.Response also keeps bodyclose
// from misfiring on every caller — the linter cannot see through a
// helper that closes the body internally.
type rawResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func (c *GitHubAccessConnector) doRaw(req *http.Request) (*rawResponse, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	r := &rawResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       body,
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return r, fmt.Errorf("github: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return r, nil
}

func (c *GitHubAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *GitHubAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.baseURL()+"/orgs/"+cfg.Organization)
	if err != nil {
		return err
	}
	if _, err := c.doRaw(req); err != nil {
		return fmt.Errorf("github: connect probe: %w", err)
	}
	return nil
}

func (c *GitHubAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type githubMember struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Type  string `json:"type"`
}

func (c *GitHubAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

// linkNextPattern parses a `Link: <url>; rel="next", ...` header for the next page URL.
var linkNextPattern = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func parseNextLink(linkHeader string) string {
	m := linkNextPattern.FindStringSubmatch(linkHeader)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func (c *GitHubAccessConnector) SyncIdentities(
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
		nextURL = c.baseURL() + "/orgs/" + cfg.Organization + "/members?per_page=100"
	}
	for {
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}
		var members []githubMember
		if err := json.Unmarshal(resp.Body, &members); err != nil {
			return fmt.Errorf("github: decode members: %w", err)
		}
		identities := make([]*access.Identity, 0, len(members))
		for _, m := range members {
			idType := access.IdentityTypeUser
			if strings.EqualFold(m.Type, "Bot") {
				idType = access.IdentityTypeServiceAccount
			}
			identities = append(identities, &access.Identity{
				ExternalID:  fmt.Sprintf("%d", m.ID),
				Type:        idType,
				DisplayName: m.Login,
				Email:       "",
				Status:      "active",
			})
		}
		next := parseNextLink(resp.Header.Get("Link"))
		// rewrite next URL when running against urlOverride: GitHub returns
		// absolute URLs that point at api.github.com — swap them for the
		// httptest server host so tests stay hermetic.
		if next != "" && c.urlOverride != "" {
			next = strings.Replace(next, defaultBaseURL, strings.TrimRight(c.urlOverride, "/"), 1)
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

// ProvisionAccess adds a user to an org team via PUT /orgs/{org}/teams/{team_slug}/memberships/{username}.
func (c *GitHubAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("github: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	role := grant.Role
	if role == "" {
		role = "member"
	}
	body, _ := json.Marshal(map[string]string{"role": role})
	urlStr := fmt.Sprintf("%s/orgs/%s/teams/%s/memberships/%s",
		c.baseURL(), url.PathEscape(cfg.Organization),
		url.PathEscape(grant.ResourceExternalID), url.PathEscape(grant.UserExternalID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, urlStr, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("github: provision request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		return nil
	}
	return fmt.Errorf("github: provision status %d: %s", resp.StatusCode, string(respBody))
}

// RevokeAccess removes a user from an org team. 404 = idempotent.
func (c *GitHubAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("github: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	urlStr := fmt.Sprintf("%s/orgs/%s/teams/%s/memberships/%s",
		c.baseURL(), url.PathEscape(cfg.Organization),
		url.PathEscape(grant.ResourceExternalID), url.PathEscape(grant.UserExternalID))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, urlStr, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))

	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("github: revoke request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("github: revoke status %d: %s", resp.StatusCode, string(respBody))
}

// ListEntitlements returns org membership + team memberships for a user.
func (c *GitHubAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("github: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	var out []access.Entitlement

	// Org membership
	urlStr := fmt.Sprintf("%s/orgs/%s/memberships/%s", c.baseURL(), url.PathEscape(cfg.Organization), url.PathEscape(userExternalID))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, urlStr)
	if err != nil {
		return nil, err
	}
	respOrg, err := c.doRaw(req)
	if err == nil {
		var m struct {
			Role  string `json:"role"`
			State string `json:"state"`
		}
		if json.Unmarshal(respOrg.Body, &m) == nil {
			out = append(out, access.Entitlement{
				ResourceExternalID: cfg.Organization,
				Role:               m.Role,
				Source:             "direct",
			})
		}
	}

	// Team memberships
	nextURL := fmt.Sprintf("%s/orgs/%s/teams", c.baseURL(), url.PathEscape(cfg.Organization))
	for nextURL != "" {
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return nil, err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			break
		}
		var teams []struct {
			Slug string `json:"slug"`
		}
		if json.Unmarshal(resp.Body, &teams) != nil {
			break
		}
		for _, team := range teams {
			mURL := fmt.Sprintf("%s/orgs/%s/teams/%s/memberships/%s",
				c.baseURL(), url.PathEscape(cfg.Organization),
				url.PathEscape(team.Slug), url.PathEscape(userExternalID))
			mReq, err := c.newRequest(ctx, secrets, http.MethodGet, mURL)
			if err != nil {
				continue
			}
			mResp, err := c.doRaw(mReq)
			if err != nil {
				continue
			}
			var mem struct {
				Role string `json:"role"`
			}
			if json.Unmarshal(mResp.Body, &mem) == nil {
				out = append(out, access.Entitlement{
					ResourceExternalID: team.Slug,
					Role:               mem.Role,
					Source:             "direct",
				})
			}
		}
		nextURL = parseNextLink(resp.Header.Get("Link"))
	}
	return out, nil
}

// parseLinkNext was a duplicate of parseNextLink that took the live
// *http.Response instead of the Link header string. It was removed
// when doRaw started returning the body-closed rawResponse snapshot,
// since all pagination call sites can now pass resp.Header.Get("Link")
// directly to parseNextLink.
//
// Intentionally left as a comment, not a wrapper, so a future caller
// reaches for the canonical helper rather than recreating the alias.

// GetSSOMetadata returns the SAML SSO metadata URL for GitHub Enterprise
// Cloud organisations. GitHub publishes metadata at
// `https://github.com/organizations/{org}/saml/metadata`.
func (c *GitHubAccessConnector) GetSSOMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, _, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return &access.SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://github.com/organizations/" + cfg.Organization + "/saml/metadata",
		EntityID:    "https://github.com/orgs/" + cfg.Organization,
	}, nil
}

func (c *GitHubAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":     ProviderName,
		"organization": cfg.Organization,
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

var _ access.AccessConnector = (*GitHubAccessConnector)(nil)
