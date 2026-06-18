// Package slack implements the access.AccessConnector contract for the
// Slack workspace users API.
package slack

import (
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
	ProviderName   = "slack"
	defaultBaseURL = "https://slack.com/api"
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	TeamID string `json:"team_id,omitempty"`
}

type Secrets struct {
	BotToken string `json:"bot_token"`
}

type SlackAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *SlackAccessConnector { return &SlackAccessConnector{} }
func init()                      { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, nil
	}
	var cfg Config
	if v, ok := raw["team_id"].(string); ok {
		cfg.TeamID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("slack: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["bot_token"].(string); ok {
		s.BotToken = v
	}
	return s, nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.BotToken) == "" {
		return errors.New("slack: bot_token is required")
	}
	if !strings.HasPrefix(s.BotToken, "xoxb-") && !strings.HasPrefix(s.BotToken, "xoxa-") && !strings.HasPrefix(s.BotToken, "xoxp-") {
		return errors.New("slack: bot_token must start with xoxb-/xoxa-/xoxp-")
	}
	return nil
}

func (c *SlackAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
	if _, err := DecodeConfig(configRaw); err != nil {
		return err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return err
	}
	return s.validate()
}

func (c *SlackAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *SlackAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *SlackAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.BotToken))
	return req, nil
}

type slackAPIResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (c *SlackAccessConnector) do(req *http.Request) ([]byte, error) {
	body, apiErr, err := c.doWithAPIError(req)
	if err != nil {
		return nil, err
	}
	if apiErr != "" {
		return nil, fmt.Errorf("slack: %s %s: api error: %s", req.Method, req.URL.Path, apiErr)
	}
	return body, nil
}

func (c *SlackAccessConnector) doWithAPIError(req *http.Request) (body []byte, apiErr string, err error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("slack: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", fmt.Errorf("slack: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	var envelope slackAPIResponse
	if err := json.Unmarshal(body, &envelope); err == nil && !envelope.OK {
		return body, envelope.Error, nil
	}
	return body, "", nil
}

func (c *SlackAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *SlackAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/auth.test")
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("slack: connect probe: %w", err)
	}
	return nil
}

func (c *SlackAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type slackUsersResponse struct {
	OK               bool        `json:"ok"`
	Error            string      `json:"error,omitempty"`
	Members          []slackUser `json:"members"`
	ResponseMetadata struct {
		NextCursor string `json:"next_cursor"`
	} `json:"response_metadata"`
}

type slackUser struct {
	ID       string `json:"id"`
	TeamID   string `json:"team_id"`
	Name     string `json:"name"`
	RealName string `json:"real_name"`
	Deleted  bool   `json:"deleted"`
	IsBot    bool   `json:"is_bot"`
	Profile  struct {
		Email       string `json:"email,omitempty"`
		DisplayName string `json:"display_name,omitempty"`
	} `json:"profile"`
}

type slackTeamInfoResponse struct {
	OK   bool `json:"ok"`
	Team struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Domain      string `json:"domain"`
		EnterprID   string `json:"enterprise_id,omitempty"`
		EnterprName string `json:"enterprise_name,omitempty"`
	} `json:"team"`
}

func (c *SlackAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	// users.list is the only authoritative source; iterate.
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *SlackAccessConnector) SyncIdentities(
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
		q := url.Values{}
		q.Set("limit", "200")
		if cfg.TeamID != "" {
			q.Set("team_id", cfg.TeamID)
		}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		path := "/users.list?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp slackUsersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("slack: decode users.list: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Members))
		for _, m := range resp.Members {
			display := m.Profile.DisplayName
			if display == "" {
				display = m.RealName
			}
			if display == "" {
				display = m.Name
			}
			idType := access.IdentityTypeUser
			if m.IsBot {
				idType = access.IdentityTypeServiceAccount
			}
			status := "active"
			if m.Deleted {
				status = "deleted"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  m.ID,
				Type:        idType,
				DisplayName: display,
				Email:       m.Profile.Email,
				Status:      status,
			})
		}
		next := resp.ResponseMetadata.NextCursor
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}

// ProvisionAccess invites a user to a Slack channel via conversations.invite.
// grant.ResourceExternalID = channel ID, grant.UserExternalID = user ID.
// already_in_channel is treated as idempotent success.
func (c *SlackAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("slack: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	form := url.Values{}
	form.Set("channel", grant.ResourceExternalID)
	form.Set("users", grant.UserExternalID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL()+"/conversations.invite", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.BotToken))

	_, apiErr, err := c.doWithAPIError(req)
	if err != nil {
		return err
	}
	if apiErr == "" || apiErr == "already_in_channel" {
		return nil
	}
	return fmt.Errorf("slack: conversations.invite: api error: %s", apiErr)
}

// RevokeAccess removes a user from a Slack channel via conversations.kick.
// not_in_channel is treated as idempotent success.
func (c *SlackAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("slack: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	form := url.Values{}
	form.Set("channel", grant.ResourceExternalID)
	form.Set("user", grant.UserExternalID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL()+"/conversations.kick", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.BotToken))

	_, apiErr, err := c.doWithAPIError(req)
	if err != nil {
		return err
	}
	if apiErr == "" || apiErr == "not_in_channel" {
		return nil
	}
	return fmt.Errorf("slack: conversations.kick: api error: %s", apiErr)
}

// ListEntitlements fetches the channels a user belongs to via users.conversations
// and maps each channel to an Entitlement with Role = "member".
func (c *SlackAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("slack: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	var out []access.Entitlement
	cursor := ""
	for {
		q := url.Values{}
		q.Set("user", userExternalID)
		q.Set("limit", "200")
		q.Set("types", "public_channel,private_channel")
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		path := "/users.conversations?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return nil, err
		}
		body, err := c.do(req)
		if err != nil {
			return nil, err
		}
		var resp struct {
			OK       bool `json:"ok"`
			Channels []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"channels"`
			ResponseMetadata struct {
				NextCursor string `json:"next_cursor"`
			} `json:"response_metadata"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("slack: decode users.conversations: %w", err)
		}
		for _, ch := range resp.Channels {
			out = append(out, access.Entitlement{
				ResourceExternalID: ch.ID,
				Role:               "member",
				Source:             "direct",
			})
		}
		if resp.ResponseMetadata.NextCursor == "" {
			break
		}
		cursor = resp.ResponseMetadata.NextCursor
	}
	return out, nil
}

// GetSSOMetadata returns SAML metadata for Enterprise Grid workspaces.
// For non-Enterprise plans, it returns nil, nil (no SSO surface published).
func (c *SlackAccessConnector) GetSSOMetadata(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (*access.SSOMetadata, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/team.info")
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, nil
	}
	var info slackTeamInfoResponse
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, nil
	}
	if info.Team.EnterprID == "" {
		return nil, nil
	}
	return &access.SSOMetadata{
		Protocol:    "saml",
		MetadataURL: fmt.Sprintf("https://%s.slack.com/sso/saml/metadata", info.Team.Domain),
		EntityID:    fmt.Sprintf("https://slack.com/%s", info.Team.EnterprID),
	}, nil
}

func (c *SlackAccessConnector) GetCredentialsMetadata(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "bot_token",
		"token_short": shortToken(secrets.BotToken),
	}
	if cfg.TeamID != "" {
		out["team_id"] = cfg.TeamID
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/auth.test")
	if err != nil {
		return out, nil
	}
	body, err := c.do(req)
	if err != nil {
		return out, nil
	}
	var resp struct {
		OK     bool   `json:"ok"`
		Team   string `json:"team,omitempty"`
		User   string `json:"user,omitempty"`
		TeamID string `json:"team_id,omitempty"`
		UserID string `json:"user_id,omitempty"`
	}
	if err := json.Unmarshal(body, &resp); err == nil && resp.OK {
		out["team"] = resp.Team
		out["bot_user"] = resp.User
		out["bot_user_id"] = resp.UserID
		if resp.TeamID != "" {
			out["resolved_team_id"] = resp.TeamID
		}
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

var _ access.AccessConnector = (*SlackAccessConnector)(nil)
