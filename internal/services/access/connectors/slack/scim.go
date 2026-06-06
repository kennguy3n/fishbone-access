// Package slack — SCIM v2.0 outbound provisioning composition.
//
// Slack Business+ workspaces (and any Enterprise Grid org with SCIM
// enabled) expose a SCIM 2.0 endpoint at
// `https://api.slack.com/scim/v2/Users` and `/Groups`. The endpoint
// is gated on the workspace plan and requires a dedicated SCIM
// bearer token (typically a `xoxs-...` or workspace-admin OAuth
// token with `users:scim:write` + `groups:scim:write` scopes) minted
// by a Workspace Owner. The standard bot token (`xoxb-`) does NOT
// have permission to call the SCIM endpoint, so we surface the SCIM
// token as a distinct `scim_token` secret and require it explicitly.
package slack

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const slackSCIMDefaultBaseURL = "https://api.slack.com/scim/v2"

var (
	scimClientOnce sync.Once
	scimClient     *access.SCIMClient
)

func scim() *access.SCIMClient {
	scimClientOnce.Do(func() {
		scimClient = access.NewSCIMClient()
	})
	return scimClient
}

// SetSCIMClientForTest swaps the package-level SCIMClient and returns
// the previous one so tests can restore it on cleanup.
func SetSCIMClientForTest(c *access.SCIMClient) *access.SCIMClient {
	prev := scim()
	scimClient = c
	return prev
}

// scimConfig adapts the Slack workspace config + secrets into the
// shared SCIMClient's `scim_base_url` + `scim_auth_header` pair. The
// SCIM base URL defaults to `https://api.slack.com/scim/v2`; operators
// can override it via `configRaw["scim_base_url"]` (matches the AWS
// SCIM convention — URLs live in config, not secrets) and tests
// override it via the connector's `urlOverride` (matches the audit
// log + connector wiring). The `scim_token` secret is mandatory.
func (c *SlackAccessConnector) scimConfig(_ Config, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	token, _ := secretsRaw["scim_token"].(string)
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil, errors.New("slack: scim_token is required for SCIM provisioning")
	}
	base := slackSCIMDefaultBaseURL
	if override, ok := configRaw["scim_base_url"].(string); ok {
		if v := strings.TrimSpace(override); v != "" {
			base = strings.TrimRight(v, "/")
		}
	}
	if c.urlOverride != "" {
		base = strings.TrimRight(c.urlOverride, "/") + "/scim/v2"
	}
	return map[string]interface{}{
			"scim_base_url": base,
		}, map[string]interface{}{
			"scim_auth_header": "Bearer " + strings.TrimPrefix(token, "Bearer "),
		}, nil
}

// PushSCIMUser satisfies access.SCIMProvisioner.
func (c *SlackAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
	cfg, _, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	scimCfg, scimSecrets, err := c.scimConfig(cfg, configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMUser(ctx, scimCfg, scimSecrets, user)
}

// PushSCIMGroup satisfies access.SCIMProvisioner.
func (c *SlackAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
	cfg, _, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	scimCfg, scimSecrets, err := c.scimConfig(cfg, configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMGroup(ctx, scimCfg, scimSecrets, group)
}

// DeleteSCIMResource satisfies access.SCIMProvisioner.
func (c *SlackAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
	cfg, _, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	scimCfg, scimSecrets, err := c.scimConfig(cfg, configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, resourceType, externalID)
}

var _ access.SCIMProvisioner = (*SlackAccessConnector)(nil)
