// Package miro implements the access.AccessConnector contract for the
// Miro org members API.
package miro

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
	ProviderName   = "miro"
	defaultBaseURL = "https://api.miro.com/v2"
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	OrgID string `json:"org_id"`
}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type MiroAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *MiroAccessConnector { return &MiroAccessConnector{} }
func init()                     { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("miro: config is nil")
	}
	var cfg Config
	if v, ok := raw["org_id"].(string); ok {
		cfg.OrgID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("miro: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_token"].(string); ok {
		s.AccessToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.OrgID) == "" {
		return errors.New("miro: org_id is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("miro: access_token is required")
	}
	return nil
}

func (c *MiroAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *MiroAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *MiroAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *MiroAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *MiroAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, path string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *MiroAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("miro: %s %s: %w", req.Method, req.URL.Path, err)
	}
	return resp, nil
}

func (c *MiroAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("miro: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("miro: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *MiroAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *MiroAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/orgs/"+cfg.OrgID)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("miro: connect probe: %w", err)
	}
	return nil
}

func (c *MiroAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type miroMembersResponse struct {
	Data   []miroMember `json:"data"`
	Cursor string       `json:"cursor,omitempty"`
}

type miroMember struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
	Type  string `json:"type"`
	Name  string `json:"name,omitempty"`
}

func (c *MiroAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *MiroAccessConnector) SyncIdentities(
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
	for {
		path := "/orgs/" + url.PathEscape(cfg.OrgID) + "/members?limit=100"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp miroMembersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("miro: decode members: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Data))
		for _, m := range resp.Data {
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
		next := resp.Cursor
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

type miroTeamsListResponse struct {
	Data   []miroTeam `json:"data"`
	Cursor string     `json:"cursor,omitempty"`
}

type miroTeam struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	Role string `json:"role,omitempty"`
}

// resolveMemberEmail returns the email address used when adding a user to
// a Miro team. The Miro POST /orgs/{org_id}/teams/{team_id}/members API
// only accepts emails, so if grant.UserExternalID was emitted by
// SyncIdentities (a Miro member ID), we resolve it to an email via
// GET /orgs/{org_id}/members/{member_id} before composing the payload.
// If the caller already passed an email, it is returned as-is.
func (c *MiroAccessConnector) resolveMemberEmail(ctx context.Context, cfg Config, secrets Secrets, userExternalID string) (string, error) {
	if strings.Contains(userExternalID, "@") {
		return userExternalID, nil
	}
	path := "/orgs/" + url.PathEscape(cfg.OrgID) + "/members/" + url.PathEscape(userExternalID)
	req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
	if err != nil {
		return "", err
	}
	body, err := c.do(req)
	if err != nil {
		return "", fmt.Errorf("miro: resolve email for member %q: %w", userExternalID, err)
	}
	var m miroMember
	if err := json.Unmarshal(body, &m); err != nil {
		return "", fmt.Errorf("miro: decode member %q: %w", userExternalID, err)
	}
	if strings.TrimSpace(m.Email) == "" {
		return "", fmt.Errorf("miro: member %q has no email on record", userExternalID)
	}
	return m.Email, nil
}

// resolveMemberID returns the Miro member ID used in URL paths for
// DELETE .../teams/{team_id}/members/{member_id} and
// GET .../members/{member_id}/teams. If userExternalID does not contain
// "@" it is treated as a member ID and returned as-is. Otherwise the
// connector paginates GET /orgs/{org_id}/members looking for a case-
// insensitive email match. Returns ("", nil) when no member matches, so
// callers can short-circuit revoke and list-entitlements as idempotent.
func (c *MiroAccessConnector) resolveMemberID(ctx context.Context, cfg Config, secrets Secrets, userExternalID string) (string, error) {
	if !strings.Contains(userExternalID, "@") {
		return userExternalID, nil
	}
	cursor := ""
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		path := "/orgs/" + url.PathEscape(cfg.OrgID) + "/members?limit=100"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return "", err
		}
		body, err := c.do(req)
		if err != nil {
			return "", fmt.Errorf("miro: resolve member ID for email %q: %w", userExternalID, err)
		}
		var resp miroMembersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", fmt.Errorf("miro: decode members: %w", err)
		}
		for _, m := range resp.Data {
			if strings.EqualFold(m.Email, userExternalID) {
				return m.ID, nil
			}
		}
		if resp.Cursor == "" {
			return "", nil
		}
		cursor = resp.Cursor
	}
}

// ProvisionAccess adds a user to a Miro team via
// POST /orgs/{org_id}/teams/{team_id}/members. The team_id comes from
// grant.ResourceExternalID. grant.UserExternalID may be either an email
// or a Miro member ID (canonical form emitted by SyncIdentities); when a
// member ID is supplied, the connector resolves the email first since the
// Miro v2 API only accepts emails on this endpoint.
func (c *MiroAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("miro: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("miro: grant.ResourceExternalID (team_id) is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	email, err := c.resolveMemberEmail(ctx, cfg, secrets, grant.UserExternalID)
	if err != nil {
		return err
	}
	role := "member"
	if strings.EqualFold(grant.Role, "admin") {
		role = "admin"
	}
	payload := map[string]interface{}{
		"members": []map[string]string{{"email": email, "role": role}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("miro: marshal payload: %w", err)
	}
	path := "/orgs/" + url.PathEscape(cfg.OrgID) + "/teams/" + url.PathEscape(grant.ResourceExternalID) + "/members"
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, path, body)
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
		return fmt.Errorf("miro: team add member status %d: %s", resp.StatusCode, string(respBody))
	}
}

// RevokeAccess removes a user from a Miro team via
// DELETE /orgs/{org_id}/teams/{team_id}/members/{member_id}. 404 is idempotent.
// grant.UserExternalID may be either a member ID (canonical) or an email;
// when given an email the connector resolves the member ID via the org
// members listing first. An email that does not match any current org
// member is treated as already-revoked.
func (c *MiroAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("miro: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("miro: grant.ResourceExternalID (team_id) is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	memberID, err := c.resolveMemberID(ctx, cfg, secrets, grant.UserExternalID)
	if err != nil {
		return err
	}
	if memberID == "" {
		return nil
	}
	path := "/orgs/" + url.PathEscape(cfg.OrgID) + "/teams/" + url.PathEscape(grant.ResourceExternalID) + "/members/" + url.PathEscape(memberID)
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, path)
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
		return fmt.Errorf("miro: team remove member status %d: %s", resp.StatusCode, string(respBody))
	}
}

// ListEntitlements paginates GET /v2/orgs/{org_id}/members/{user_id}/teams
// and emits one Entitlement per team membership. Role defaults to "member"
// when unspecified by the API.
func (c *MiroAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return nil, errors.New("miro: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	memberID, err := c.resolveMemberID(ctx, cfg, secrets, userExternalID)
	if err != nil {
		return nil, err
	}
	if memberID == "" {
		return nil, nil
	}
	var out []access.Entitlement
	cursor := ""
	for {
		path := "/orgs/" + url.PathEscape(cfg.OrgID) + "/members/" + url.PathEscape(memberID) + "/teams?limit=100"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return nil, err
		}
		body, err := c.do(req)
		if err != nil {
			return nil, err
		}
		var resp miroTeamsListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("miro: decode teams: %w", err)
		}
		for _, t := range resp.Data {
			role := strings.ToLower(t.Role)
			if role == "" {
				role = "member"
			}
			out = append(out, access.Entitlement{
				ResourceExternalID: t.ID,
				Role:               role,
				Source:             "direct",
			})
		}
		if resp.Cursor == "" {
			return out, nil
		}
		cursor = resp.Cursor
	}
}

// GetSSOMetadata returns Miro SAML federation metadata when the operator
// supplies `sso_metadata_url` in the connector config.
func (c *MiroAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *MiroAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"org_id":      cfg.OrgID,
		"auth_type":   "access_token",
		"token_short": shortToken(secrets.AccessToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*MiroAccessConnector)(nil)
