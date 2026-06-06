// Package clickup implements the access.AccessConnector contract for the
// ClickUp team members API.
package clickup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const ProviderName = "clickup"

var ErrNotImplemented = fmt.Errorf("clickup: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	TeamID string `json:"team_id"`
}

type Secrets struct {
	APIToken string `json:"api_token"`
}

type ClickUpAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *ClickUpAccessConnector { return &ClickUpAccessConnector{} }
func init()                        { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("clickup: config is nil")
	}
	var cfg Config
	if v, ok := raw["team_id"].(string); ok {
		cfg.TeamID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("clickup: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_token"].(string); ok {
		s.APIToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.TeamID) == "" {
		return errors.New("clickup: team_id is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIToken) == "" {
		return errors.New("clickup: api_token is required")
	}
	return nil
}

func (c *ClickUpAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *ClickUpAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.clickup.com"
}

func (c *ClickUpAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *ClickUpAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", strings.TrimSpace(secrets.APIToken))
	return req, nil
}

func (c *ClickUpAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", strings.TrimSpace(secrets.APIToken))
	return req, nil
}

func (c *ClickUpAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("clickup: %s %s: %w", req.Method, req.URL.Path, err)
	}
	return resp, nil
}

func (c *ClickUpAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("clickup: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("clickup: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *ClickUpAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *ClickUpAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := fmt.Sprintf("%s/api/v2/team/%s", c.baseURL(), url.PathEscape(cfg.TeamID))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("clickup: connect probe: %w", err)
	}
	return nil
}

func (c *ClickUpAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type clickupUser struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
	Name  string `json:"username"`
	Role  int    `json:"role"`
}

type clickupMember struct {
	User clickupUser `json:"user"`
}

type clickupResponse struct {
	Members []clickupMember `json:"members"`
}

func (c *ClickUpAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *ClickUpAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	memberURL := fmt.Sprintf("%s/api/v2/team/%s/member", c.baseURL(), url.PathEscape(cfg.TeamID))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, memberURL)
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	var resp clickupResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("clickup: decode members: %w", err)
	}
	identities := make([]*access.Identity, 0, len(resp.Members))
	for _, m := range resp.Members {
		display := m.User.Name
		if display == "" {
			display = m.User.Email
		}
		identities = append(identities, &access.Identity{
			ExternalID:  fmt.Sprintf("%d", m.User.ID),
			Type:        access.IdentityTypeUser,
			DisplayName: display,
			Email:       m.User.Email,
			Status:      "active",
		})
	}
	return handler(identities, "")
}

// ---------- advanced capabilities ----------

// ProvisionAccess adds a user to a ClickUp List via
// POST /api/v2/list/{list_id}/member with body {"user_id": <id>}.
// Already-member responses (409 or "already a member" text) are treated
// as idempotent success.
func (c *ClickUpAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("clickup: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("clickup: grant.ResourceExternalID (list_id) is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	userID, err := strconv.ParseInt(grant.UserExternalID, 10, 64)
	if err != nil {
		return fmt.Errorf("clickup: user external id must be numeric: %w", err)
	}
	body, err := json.Marshal(map[string]int64{"user_id": userID})
	if err != nil {
		return fmt.Errorf("clickup: marshal payload: %w", err)
	}
	fullURL := c.baseURL() + "/api/v2/list/" + url.PathEscape(grant.ResourceExternalID) + "/member"
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, fullURL, body)
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
		return fmt.Errorf("clickup: list member POST status %d: %s", resp.StatusCode, string(respBody))
	}
}

// RevokeAccess removes a user from a ClickUp List via
// DELETE /api/v2/list/{list_id}/member/{user_id}. 404 is idempotent.
func (c *ClickUpAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("clickup: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("clickup: grant.ResourceExternalID (list_id) is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	fullURL := c.baseURL() + "/api/v2/list/" + url.PathEscape(grant.ResourceExternalID) + "/member/" + url.PathEscape(grant.UserExternalID)
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, fullURL)
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
		return fmt.Errorf("clickup: list member DELETE status %d: %s", resp.StatusCode, string(respBody))
	}
}

// ListEntitlements walks the workspace's spaces and emits one Entitlement
// per space the user is a member of. ClickUp's per-user list endpoint
// requires a personal token scope we may not have, so we read the team
// membership and synthesize one space-level Entitlement when the user
// belongs to the workspace.
func (c *ClickUpAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return nil, errors.New("clickup: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	fullURL := c.baseURL() + "/api/v2/team/" + url.PathEscape(cfg.TeamID) + "/member"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var resp clickupResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("clickup: decode members: %w", err)
	}
	var out []access.Entitlement
	for _, m := range resp.Members {
		if fmt.Sprintf("%d", m.User.ID) != userExternalID && !strings.EqualFold(m.User.Email, userExternalID) {
			continue
		}
		role := clickupRoleName(m.User.Role)
		out = append(out, access.Entitlement{
			ResourceExternalID: cfg.TeamID,
			Role:               role,
			Source:             "direct",
		})
	}
	return out, nil
}

func clickupRoleName(role int) string {
	switch role {
	case 1:
		return "owner"
	case 2:
		return "admin"
	case 3:
		return "member"
	case 4:
		return "guest"
	default:
		return "member"
	}
}

// GetSSOMetadata returns ClickUp SAML federation metadata when the
// operator supplies `sso_metadata_url` in the connector config.
func (c *ClickUpAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *ClickUpAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"team_id":     cfg.TeamID,
		"auth_type":   "api_token",
		"token_short": shortToken(secrets.APIToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		// Never echo a short secret verbatim: GetCredentialsMetadata is a
		// non-sensitive fingerprint surfaced in the admin UI/logs, so a
		// ≤8-char token must be fully masked rather than returned as-is.
		return strings.Repeat("*", len(t))
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*ClickUpAccessConnector)(nil)
