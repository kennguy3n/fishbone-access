// Package tailscale — SCIM v2.0 outbound provisioning composition.
//
// Tailscale exposes a SCIM 2.0 endpoint per tailnet at
// https://api.tailscale.com/api/v2/tailnet/{tailnet}/scim/v2/. The
// endpoint is gated to tailnets with their SCIM provisioning module
// enabled and uses a dedicated SCIM bearer (an OAuth client token
// with the `scim` scope, or a tailnet API access token with the
// `scim` scope) distinct from the api_key used for sync; we surface
// that token as the `scim_token` secret.
package tailscale

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

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

// tailscaleSCIMBaseURL derives the SCIM base URL from the existing
// Config.Tailnet field so a tenant doesn't need to configure SCIM
// hosting separately. Operators may still override via the
// `scim_base_url` *config* key for test fixtures / proxies (NOT
// secrets — URLs are configuration, not credentials).
func tailscaleSCIMBaseURL(cfg Config) string {
	return "https://api.tailscale.com/api/v2/tailnet/" + url.PathEscape(strings.TrimSpace(cfg.Tailnet)) + "/scim/v2"
}

// scimConfig adapts per-tenant config + secrets into the
// scim_base_url + scim_auth_header pair. base URL is overridable
// for self-hosted SCIM proxies and tests via the `scim_base_url`
// *config* key (NOT secret — endpoints are configuration, not
// credentials, matching the convention used by aws/datadog/zendesk/
// knowbe4/pagerduty). The auth header is always `Bearer
// {scim_token}` where `scim_token` lives in secrets.
func (c *TailscaleAccessConnector) scimConfig(cfg Config, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	token, _ := secretsRaw["scim_token"].(string)
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil, errors.New("tailscale: scim_token is required for SCIM provisioning")
	}
	base := tailscaleSCIMBaseURL(cfg)
	if override, ok := configRaw["scim_base_url"].(string); ok {
		if v := strings.TrimSpace(override); v != "" {
			base = strings.TrimRight(v, "/")
		}
	}
	if c.urlOverride != "" {
		base = strings.TrimRight(c.urlOverride, "/") + "/api/v2/tailnet/" + url.PathEscape(strings.TrimSpace(cfg.Tailnet)) + "/scim/v2"
	}
	return map[string]interface{}{
			"scim_base_url": base,
		}, map[string]interface{}{
			"scim_auth_header": "Bearer " + token,
		}, nil
}

func (c *TailscaleAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
	cfg, _, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	scimCfg, scimSecrets, err := c.scimConfig(cfg, configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMUser(ctx, scimCfg, scimSecrets, user)
}

func (c *TailscaleAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
	cfg, _, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	scimCfg, scimSecrets, err := c.scimConfig(cfg, configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMGroup(ctx, scimCfg, scimSecrets, group)
}

func (c *TailscaleAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
	cfg, _, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	scimCfg, scimSecrets, err := c.scimConfig(cfg, configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, resourceType, externalID)
}

var _ access.SCIMProvisioner = (*TailscaleAccessConnector)(nil)
