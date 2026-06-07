// Package sentry implements the access.AccessConnector contract for the
// Sentry organization members API.
package sentry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"bytes"

	"net/url"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName   = "sentry"
	defaultBaseURL = "https://sentry.io"
)

var ErrNotImplemented = fmt.Errorf("sentry: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	OrganizationSlug string `json:"organization_slug"`
}

type Secrets struct {
	AuthToken string `json:"auth_token"`
}

type SentryAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *SentryAccessConnector { return &SentryAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("sentry: config is nil")
	}
	var cfg Config
	if v, ok := raw["organization_slug"].(string); ok {
		cfg.OrganizationSlug = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("sentry: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["auth_token"].(string); ok {
		s.AuthToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.OrganizationSlug) == "" {
		return errors.New("sentry: organization_slug is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AuthToken) == "" {
		return errors.New("sentry: auth_token is required")
	}
	return nil
}

func (c *SentryAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *SentryAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

// assertSameHost verifies that an absolute URL we are about to follow with
// the auth token targets the same host as baseURL(). SyncIdentities resumes
// from a caller-supplied checkpoint and walks the rel="next" Link header, both
// of which are absolute URLs persisted from a prior API response. Because
// newRequest attaches the token to every request, a checkpoint (or tampered
// Link header) pointing off-host would leak the bearer token to an unexpected
// host. Sentry always paginates on the request host, so an off-host URL is
// rejected rather than followed. Mirrors the azure guard.
func (c *SentryAccessConnector) assertSameHost(absoluteURL string) error {
	u, err := url.Parse(absoluteURL)
	if err != nil {
		return fmt.Errorf("sentry: parse url %q: %w", absoluteURL, err)
	}
	base, err := url.Parse(c.baseURL())
	if err != nil {
		return fmt.Errorf("sentry: parse base url: %w", err)
	}
	if !strings.EqualFold(u.Host, base.Host) {
		return fmt.Errorf("sentry: refusing to follow pagination URL to unexpected host %q (expected %q)", u.Host, base.Host)
	}
	return nil
}

func (c *SentryAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *SentryAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AuthToken))
	return req, nil
}

// rawResponse holds the status, header, and drained body of a Sentry
// response. doRaw closes the live *http.Response.Body inside the
// helper and returns this primitive snapshot so callers can read the
// Link header (cursor-based pagination) and the StatusCode without
// needing to manage body lifetime. See gitlab/connector.go for the
// same pattern; this keeps bodyclose quiet on every caller.
type rawResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func (c *SentryAccessConnector) doRaw(req *http.Request) (*rawResponse, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("sentry: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	r := &rawResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       body,
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return r, fmt.Errorf("sentry: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return r, nil
}

func (c *SentryAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *SentryAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/api/0/organizations/" + url.PathEscape(cfg.OrganizationSlug) + "/"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.doRaw(req); err != nil {
		return fmt.Errorf("sentry: connect probe: %w", err)
	}
	return nil
}

func (c *SentryAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type sentryMember struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

// Sentry uses RFC 5988 Link headers with `results="true"` / `cursor="..."` markers:
// `<URL>; rel="next"; results="true"; cursor="100:0:0"`.
var sentryLinkPattern = regexp.MustCompile(`<([^>]+)>;\s*rel="next";[^,]*results="(true|false)"`)

func parseSentryNext(linkHeader string) string {
	m := sentryLinkPattern.FindStringSubmatch(linkHeader)
	if len(m) < 3 {
		return ""
	}
	if m[2] != "true" {
		return ""
	}
	return m[1]
}

func (c *SentryAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *SentryAccessConnector) SyncIdentities(
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
		nextURL = c.baseURL() + "/api/0/organizations/" + url.PathEscape(cfg.OrganizationSlug) + "/members/"
	}
	for {
		if err := c.assertSameHost(nextURL); err != nil {
			return err
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}
		var members []sentryMember
		if err := json.Unmarshal(resp.Body, &members); err != nil {
			return fmt.Errorf("sentry: decode members: %w", err)
		}
		identities := make([]*access.Identity, 0, len(members))
		for _, m := range members {
			display := m.Name
			if display == "" {
				display = m.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  m.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       m.Email,
				Status:      "active",
			})
		}
		next := parseSentryNext(resp.Header.Get("Link"))
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

func (c *SentryAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("sentry: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	role := grant.Role
	if role == "" {
		role = "member"
	}
	body, _ := json.Marshal(map[string]string{"email": grant.UserExternalID, "role": role})
	urlStr := fmt.Sprintf("%s/api/0/organizations/%s/members/", c.baseURL(), url.PathEscape(cfg.OrganizationSlug))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AuthToken))
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("sentry: provision: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		return nil
	}
	if strings.Contains(string(respBody), "already") {
		return nil
	}
	return fmt.Errorf("sentry: provision status %d: %s", resp.StatusCode, string(respBody))
}

func (c *SentryAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("sentry: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	urlStr := fmt.Sprintf("%s/api/0/organizations/%s/members/%s/", c.baseURL(), url.PathEscape(cfg.OrganizationSlug), url.PathEscape(grant.UserExternalID))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, urlStr, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AuthToken))
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("sentry: revoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("sentry: revoke status %d: %s", resp.StatusCode, string(respBody))
}

func (c *SentryAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("sentry: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	urlStr := fmt.Sprintf("%s/api/0/organizations/%s/members/%s/", c.baseURL(), url.PathEscape(cfg.OrganizationSlug), url.PathEscape(userExternalID))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, urlStr)
	if err != nil {
		return nil, err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		// Member-not-found is a soft signal: the user simply holds no
		// entitlements, so return an empty list per the ListEntitlements
		// contract. Transient/server/network failures (5xx, timeouts)
		// must surface so the caller can retry rather than recording a
		// false "no access" during an upstream outage.
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	var m struct {
		Role  string   `json:"role"`
		Teams []string `json:"teams"`
	}
	if err := json.Unmarshal(resp.Body, &m); err != nil {
		return nil, fmt.Errorf("sentry: decode entitlements: %w", err)
	}
	out := []access.Entitlement{{ResourceExternalID: cfg.OrganizationSlug, Role: m.Role, Source: "direct"}}
	for _, t := range m.Teams {
		out = append(out, access.Entitlement{ResourceExternalID: t, Role: "member", Source: "direct"})
	}
	return out, nil
}

// GetSSOMetadata returns the operator-supplied SAML metadata URL if
// configured. Sentry federates SSO via SAML 2.0 from organization
// auth settings; when `sso_metadata_url` is blank the helper returns
// (nil, nil) and the caller gracefully downgrades.
func (c *SentryAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *SentryAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":          ProviderName,
		"organization_slug": cfg.OrganizationSlug,
		"auth_type":         "auth_token",
		"token_short":       shortToken(secrets.AuthToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*SentryAccessConnector)(nil)
