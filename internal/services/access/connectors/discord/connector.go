// Package discord implements the access.AccessConnector contract for the
// Discord /api/v10/guilds/{guild_id}/members API.
package discord

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
	ProviderName = "discord"
	pageSize     = 100 // Discord max is 1000 but 100 is the documented default.
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	GuildID string `json:"guild_id"`
}

type Secrets struct {
	BotToken string `json:"bot_token"`
}

type DiscordAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *DiscordAccessConnector { return &DiscordAccessConnector{} }
func init()                        { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("discord: config is nil")
	}
	var cfg Config
	if v, ok := raw["guild_id"].(string); ok {
		cfg.GuildID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("discord: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["bot_token"].(string); ok {
		s.BotToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	gid := strings.TrimSpace(c.GuildID)
	if gid == "" {
		return errors.New("discord: guild_id is required")
	}
	for _, r := range gid {
		if r < '0' || r > '9' {
			return errors.New("discord: guild_id must be a numeric snowflake")
		}
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.BotToken) == "" {
		return errors.New("discord: bot_token is required")
	}
	return nil
}

func (c *DiscordAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *DiscordAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://discord.com"
}

func (c *DiscordAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *DiscordAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bot "+strings.TrimSpace(secrets.BotToken))
	return req, nil
}

func (c *DiscordAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("discord: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("discord: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *DiscordAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *DiscordAccessConnector) membersURL(cfg Config) string {
	return fmt.Sprintf("%s/api/v10/guilds/%s/members", c.baseURL(), url.PathEscape(strings.TrimSpace(cfg.GuildID)))
}

func (c *DiscordAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.membersURL(cfg) + "?limit=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("discord: connect probe: %w", err)
	}
	return nil
}

func (c *DiscordAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type discordUser struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	GlobalName    string `json:"global_name"`
	Discriminator string `json:"discriminator"`
	Bot           bool   `json:"bot"`
}

type discordMember struct {
	User     discordUser `json:"user"`
	Nick     string      `json:"nick"`
	Roles    []string    `json:"roles"`
	JoinedAt string      `json:"joined_at"`
	Pending  bool        `json:"pending"`
}

func (c *DiscordAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *DiscordAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	after := checkpoint
	endpoint := c.membersURL(cfg)
	for {
		path := fmt.Sprintf("%s?limit=%d", endpoint, pageSize)
		if after != "" {
			path += "&after=" + url.QueryEscape(after)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var members []discordMember
		if err := json.Unmarshal(body, &members); err != nil {
			return fmt.Errorf("discord: decode members: %w", err)
		}
		identities := make([]*access.Identity, 0, len(members))
		var lastID string
		for _, m := range members {
			display := m.Nick
			if display == "" {
				display = m.User.GlobalName
			}
			if display == "" {
				display = m.User.Username
			}
			idType := access.IdentityTypeUser
			if m.User.Bot {
				idType = access.IdentityTypeServiceAccount
			}
			status := "active"
			if m.Pending {
				status = "pending"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  m.User.ID,
				Type:        idType,
				DisplayName: display,
				Status:      status,
				GroupIDs:    append([]string(nil), m.Roles...),
			})
			lastID = m.User.ID
		}
		next := ""
		if len(members) == pageSize && lastID != "" {
			next = lastID
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		after = next
	}
}

// Discord SSO federation. When `sso_metadata_url` is blank the helper returns
// (nil, nil) and the caller gracefully downgrades.
func (c *DiscordAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *DiscordAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "bot_token",
		"token_short": shortToken(secrets.BotToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*DiscordAccessConnector)(nil)
