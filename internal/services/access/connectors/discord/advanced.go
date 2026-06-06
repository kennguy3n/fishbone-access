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

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// advanced-capability mapping for Discord:
//
//   - ProvisionAccess  -> PUT    /api/v10/guilds/{guild_id}/members/{user_id}/roles/{role_id}
//   - RevokeAccess     -> DELETE /api/v10/guilds/{guild_id}/members/{user_id}/roles/{role_id}
//   - ListEntitlements -> GET    /api/v10/guilds/{guild_id}/members/{user_id}
//                         (member.roles[] is the role id list)
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Discord user snowflake
//   - grant.ResourceExternalID -> Discord role snowflake (guild id from cfg)
//
// Bot-token auth via DiscordAccessConnector.newRequest.

func discordValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("discord: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("discord: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *DiscordAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bot "+strings.TrimSpace(secrets.BotToken))
	return req, nil
}

func (c *DiscordAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("discord: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *DiscordAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := discordValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/api/v10/guilds/%s/members/%s/roles/%s",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(cfg.GuildID)),
		url.PathEscape(strings.TrimSpace(grant.UserExternalID)),
		url.PathEscape(strings.TrimSpace(grant.ResourceExternalID)))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPut, endpoint)
	if err != nil {
		return err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentProvisionStatus(status, body):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("discord: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("discord: provision status %d: %s", status, string(body))
	}
}

func (c *DiscordAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := discordValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/api/v10/guilds/%s/members/%s/roles/%s",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(cfg.GuildID)),
		url.PathEscape(strings.TrimSpace(grant.UserExternalID)),
		url.PathEscape(strings.TrimSpace(grant.ResourceExternalID)))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodDelete, endpoint)
	if err != nil {
		return err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentRevokeStatus(status, body):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("discord: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("discord: revoke status %d: %s", status, string(body))
	}
}

func (c *DiscordAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("discord: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/api/v10/guilds/%s/members/%s",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(cfg.GuildID)),
		url.PathEscape(user))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, endpoint)
	if err != nil {
		return nil, err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("discord: list member status %d: %s", status, string(body))
	}
	var member struct {
		Roles []string `json:"roles"`
		User  struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &member); err != nil {
		return nil, fmt.Errorf("discord: decode member: %w", err)
	}
	out := make([]access.Entitlement, 0, len(member.Roles))
	for _, roleID := range member.Roles {
		out = append(out, access.Entitlement{
			ResourceExternalID: strings.TrimSpace(roleID),
			Role:               "role",
			Source:             "direct",
		})
	}
	return out, nil
}
