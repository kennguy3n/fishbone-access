// Package ping_identity implements the access.AccessConnector contract for
// Ping Identity / PingOne.
//
// Capabilities:
//
//   - Validate (pure-local), Connect, VerifyPermissions
//   - CountIdentities, SyncIdentities (paginated /v1/environments/{id}/users)
//   - GetSSOMetadata (PingOne OIDC discovery URL)
//   - GetCredentialsMetadata
//   - ProvisionAccess / RevokeAccess / ListEntitlements: real
//     implementations against /v1/environments/{envID}/users/{userID}/groupMemberships.
package ping_identity

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

// ErrNotImplemented is retained for any future capability that is not yet
// implemented; ProvisionAccess / RevokeAccess / ListEntitlements no longer
// return it now that the advanced capabilities are implemented.
var ErrNotImplemented = fmt.Errorf("ping_identity: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// PingIdentityAccessConnector implements access.AccessConnector for PingOne.
type PingIdentityAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string // single base URL override used for both auth and api hosts in tests
}

// New returns a fresh connector instance.
func New() *PingIdentityAccessConnector {
	return &PingIdentityAccessConnector{}
}

// ---------- Validate / Connect / VerifyPermissions ----------

func (c *PingIdentityAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *PingIdentityAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return fmt.Errorf("ping_identity: connect token: %w", err)
	}
	probeURL := c.apiURL(cfg, fmt.Sprintf("/v1/environments/%s/users?limit=1", url.PathEscape(cfg.EnvironmentID)))
	req, err := newAuthedRequest(ctx, probeURL, token)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("ping_identity: connect probe: %w", err)
	}
	return nil
}

// VerifyPermissions probes /v1/environments/{id}/users for sync_identity.
func (c *PingIdentityAccessConnector) VerifyPermissions(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	capabilities []string,
) ([]string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return nil, fmt.Errorf("ping_identity: authenticate: %w", err)
	}
	var missing []string
	for _, cap := range capabilities {
		switch cap {
		case "sync_identity":
			probeURL := c.apiURL(cfg, fmt.Sprintf("/v1/environments/%s/users?limit=1", url.PathEscape(cfg.EnvironmentID)))
			req, err := newAuthedRequest(ctx, probeURL, token)
			if err != nil {
				return nil, err
			}
			if _, err := c.do(req); err != nil {
				missing = append(missing, fmt.Sprintf("sync_identity (%v)", err))
			}
		default:
			missing = append(missing, fmt.Sprintf("%s (no probe defined)", cap))
		}
	}
	return missing, nil
}

// ---------- Identity sync ----------

// CountIdentities reads the "count" field from the PingOne users endpoint
// (HAL). When the API omits "count" we fall back to "size".
func (c *PingIdentityAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return 0, fmt.Errorf("ping_identity: authenticate: %w", err)
	}
	probeURL := c.apiURL(cfg, fmt.Sprintf("/v1/environments/%s/users?limit=1", url.PathEscape(cfg.EnvironmentID)))
	req, err := newAuthedRequest(ctx, probeURL, token)
	if err != nil {
		return 0, err
	}
	body, err := c.do(req)
	if err != nil {
		return 0, err
	}
	var page pingUsersResponse
	if err := json.Unmarshal(body, &page); err != nil {
		return 0, fmt.Errorf("ping_identity: decode count: %w", err)
	}
	if page.Count > 0 {
		return page.Count, nil
	}
	return page.Size, nil
}

// SyncIdentities pages through /v1/environments/{id}/users using HAL
// _links.next.href cursor pagination. The checkpoint is the absolute next-href
// URL; an empty checkpoint starts at page 0.
func (c *PingIdentityAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return fmt.Errorf("ping_identity: authenticate: %w", err)
	}

	next := checkpoint
	if next == "" {
		next = c.apiURL(cfg, fmt.Sprintf("/v1/environments/%s/users?limit=100", url.PathEscape(cfg.EnvironmentID)))
	}

	for {
		if !sameOrigin(c.apiOrigin(cfg), next) {
			return fmt.Errorf("ping_identity: refusing cross-origin pagination URL %q", next)
		}
		req, err := newAuthedRequest(ctx, next, token)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var page pingUsersResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("ping_identity: decode users: %w", err)
		}
		batch := mapPingUsers(page.Embedded.Users)
		nextCheckpoint := ""
		if page.Links.Next != nil && page.Links.Next.Href != "" {
			nextCheckpoint = page.Links.Next.Href
		}
		if err := handler(batch, nextCheckpoint); err != nil {
			return err
		}
		if nextCheckpoint == "" {
			return nil
		}
		next = nextCheckpoint
	}
}

// ---------- advanced capabilities ----------

// ProvisionAccess adds the user to a PingOne group via POST
// /v1/environments/{envID}/users/{userID}/groupMemberships with body
// {"id": groupID}. 409 Conflict is treated as idempotent success.
func (c *PingIdentityAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if err := validateGrantPair(grant); err != nil {
		return err
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return fmt.Errorf("ping_identity: authenticate: %w", err)
	}
	body, err := json.Marshal(map[string]string{"id": grant.ResourceExternalID})
	if err != nil {
		return err
	}
	fullURL := c.apiURL(cfg, fmt.Sprintf("/v1/environments/%s/users/%s/groupMemberships",
		url.PathEscape(cfg.EnvironmentID), url.PathEscape(grant.UserExternalID)))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.doRaw(req)
	if err != nil {
		return fmt.Errorf("ping_identity: provision request: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusConflict:
		return nil
	default:
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("ping_identity: provision status %d: %s", resp.StatusCode, string(rb))
	}
}

// RevokeAccess removes the user from the PingOne group via DELETE
// /v1/environments/{envID}/users/{userID}/groupMemberships/{groupID}. 404 is
// idempotent success.
func (c *PingIdentityAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if err := validateGrantPair(grant); err != nil {
		return err
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return fmt.Errorf("ping_identity: authenticate: %w", err)
	}
	fullURL := c.apiURL(cfg, fmt.Sprintf("/v1/environments/%s/users/%s/groupMemberships/%s",
		url.PathEscape(cfg.EnvironmentID),
		url.PathEscape(grant.UserExternalID),
		url.PathEscape(grant.ResourceExternalID)))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, fullURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.doRaw(req)
	if err != nil {
		return fmt.Errorf("ping_identity: revoke request: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusNotFound:
		return nil
	default:
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("ping_identity: revoke status %d: %s", resp.StatusCode, string(rb))
	}
}

// ListEntitlements pages through GET
// /v1/environments/{envID}/users/{userID}/groupMemberships using HAL
// _links.next.href cursor pagination.
func (c *PingIdentityAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("ping_identity: user external id is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return nil, fmt.Errorf("ping_identity: authenticate: %w", err)
	}
	next := c.apiURL(cfg, fmt.Sprintf("/v1/environments/%s/users/%s/groupMemberships?limit=100",
		url.PathEscape(cfg.EnvironmentID), url.PathEscape(userExternalID)))
	var out []access.Entitlement
	for {
		if !sameOrigin(c.apiOrigin(cfg), next) {
			return nil, fmt.Errorf("ping_identity: refusing cross-origin pagination URL %q", next)
		}
		req, err := newAuthedRequest(ctx, next, token)
		if err != nil {
			return nil, err
		}
		body, err := c.do(req)
		if err != nil {
			return nil, err
		}
		var page pingGroupMembershipsResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("ping_identity: decode group memberships: %w", err)
		}
		for _, gm := range page.Embedded.GroupMemberships {
			out = append(out, access.Entitlement{
				ResourceExternalID: gm.ID,
				Role:               gm.Name,
				Source:             "direct",
			})
		}
		if page.Links.Next == nil || page.Links.Next.Href == "" {
			return out, nil
		}
		next = page.Links.Next.Href
	}
}

func validateGrantPair(grant access.AccessGrant) error {
	if grant.UserExternalID == "" {
		return errors.New("ping_identity: grant.UserExternalID is required")
	}
	if grant.ResourceExternalID == "" {
		return errors.New("ping_identity: grant.ResourceExternalID is required")
	}
	return nil
}

type pingGroupMembershipsResponse struct {
	Links    pingLinks            `json:"_links"`
	Embedded pingGroupsEmbeddings `json:"_embedded"`
}

type pingGroupsEmbeddings struct {
	GroupMemberships []pingGroupMembership `json:"groupMemberships"`
}

type pingGroupMembership struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ---------- Metadata ----------

func (c *PingIdentityAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	authBase := c.authURL(cfg, "/"+url.PathEscape(cfg.EnvironmentID)+"/as")
	return &access.SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: authBase + "/.well-known/openid-configuration",
		EntityID:    authBase,
		SSOLoginURL: authBase + "/authorize",
	}, nil
}

func (c *PingIdentityAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":       ProviderName,
		"client_id":      s.ClientID,
		"environment_id": cfg.EnvironmentID,
	}, nil
}

// ---------- Internal helpers ----------

func decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *PingIdentityAccessConnector) authURL(cfg Config, path string) string {
	if c.urlOverride != "" {
		return c.urlOverride + path
	}
	host, _ := regionAuthHost(cfg.Region)
	return "https://" + host + path
}

func (c *PingIdentityAccessConnector) apiURL(cfg Config, path string) string {
	if c.urlOverride != "" {
		return c.urlOverride + path
	}
	host, _ := regionAPIHost(cfg.Region)
	return "https://" + host + path
}

// apiOrigin returns the scheme://host the connector is permitted to reach for
// API calls (the test override, or the region API host). PingOne paginates by
// returning absolute _links.next.href URLs; we anchor follow-up requests to
// this origin so a spoofed or compromised response cannot redirect the bearer
// token to an attacker-controlled host.
func (c *PingIdentityAccessConnector) apiOrigin(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	host, _ := regionAPIHost(cfg.Region)
	return "https://" + host
}

// sameOrigin reports whether rawURL targets the same scheme+host as base.
func sameOrigin(base, rawURL string) bool {
	b, err := url.Parse(base)
	if err != nil || b.Host == "" {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, b.Scheme) && strings.EqualFold(u.Host, b.Host)
}

func (c *PingIdentityAccessConnector) fetchAccessToken(ctx context.Context, cfg Config, secrets Secrets) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	tokenURL := c.authURL(cfg, "/"+url.PathEscape(cfg.EnvironmentID)+"/as/token")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(secrets.ClientID, secrets.ClientSecret)

	body, err := c.do(req)
	if err != nil {
		return "", err
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("ping_identity: decode token: %w", err)
	}
	if tok.AccessToken == "" {
		return "", errors.New("ping_identity: token response missing access_token")
	}
	return tok.AccessToken, nil
}

func newAuthedRequest(ctx context.Context, fullURL, token string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func (c *PingIdentityAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("ping_identity: %s status %d: %s", req.URL.Path, resp.StatusCode, string(body))
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func (c *PingIdentityAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	if c.httpClient != nil {
		return c.httpClient().Do(req)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

func mapPingUsers(users []pingUser) []*access.Identity {
	out := make([]*access.Identity, 0, len(users))
	for _, u := range users {
		status := "active"
		if !strings.EqualFold(u.Enabled.Status(), "ENABLED") {
			status = "disabled"
		}
		out = append(out, &access.Identity{
			ExternalID:  u.ID,
			Type:        access.IdentityTypeUser,
			DisplayName: u.Name.Formatted,
			Email:       u.Email,
			Status:      status,
		})
	}
	return out
}

// ---------- PingOne DTOs ----------

type pingUsersResponse struct {
	Size     int          `json:"size,omitempty"`
	Count    int          `json:"count,omitempty"`
	Embedded pingEmbedded `json:"_embedded"`
	Links    pingLinks    `json:"_links"`
}

type pingEmbedded struct {
	Users []pingUser `json:"users"`
}

type pingLinks struct {
	Next *pingHref `json:"next,omitempty"`
	Self *pingHref `json:"self,omitempty"`
}

type pingHref struct {
	Href string `json:"href"`
}

type pingUser struct {
	ID      string      `json:"id"`
	Email   string      `json:"email"`
	Name    pingName    `json:"name"`
	Enabled pingEnabled `json:"enabled"`
}

type pingName struct {
	Formatted string `json:"formatted"`
	Given     string `json:"given,omitempty"`
	Family    string `json:"family,omitempty"`
}

// pingEnabled tolerates both string ("ENABLED"/"DISABLED") and boolean
// representations PingOne has historically returned.
type pingEnabled struct {
	Bool *bool  `json:"-"`
	Text string `json:"-"`
}

func (e *pingEnabled) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		e.Text = s
		return nil
	}
	var b bool
	if err := json.Unmarshal(data, &b); err != nil {
		return err
	}
	e.Bool = &b
	return nil
}

// Status returns "ENABLED" / "DISABLED" / "" depending on which form the
// server sent.
func (e pingEnabled) Status() string {
	if e.Text != "" {
		return e.Text
	}
	if e.Bool != nil {
		if *e.Bool {
			return "ENABLED"
		}
		return "DISABLED"
	}
	return ""
}

// MarshalJSON renders the value back to whichever form the server set, so
// that fixtures and round-trip tests stay readable.
func (e pingEnabled) MarshalJSON() ([]byte, error) {
	if e.Text != "" {
		return json.Marshal(e.Text)
	}
	if e.Bool != nil {
		return json.Marshal(*e.Bool)
	}
	return []byte("null"), nil
}

// ---------- compile-time interface assertions ----------

var (
	_ access.AccessConnector = (*PingIdentityAccessConnector)(nil)
)
