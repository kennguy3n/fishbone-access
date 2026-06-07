// Package sumo_logic — SCIM v2.0 outbound provisioning composition.
//
// Sumo Logic exposes a SCIM 2.0 endpoint at
// https://api.{deployment}.sumologic.com/api/v1/scim/v2/. The
// endpoint is gated to Sumo Logic accounts with SCIM provisioning
// enabled and uses a dedicated SCIM bearer token (distinct from the
// access-id/access-key pair used for /api/v1/users sync). We
// surface that token as the `scim_token` secret. The deployment in
// scim_base_url mirrors the deployment used for /api/v1 endpoints so
// a tenant on api.us2.sumologic.com for sync also lands on
// api.us2.sumologic.com for SCIM.
package sumo_logic

import (
	"context"
	"errors"
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

// sumoLogicSCIMBaseURL derives the SCIM base URL from the same
// deployment the /api/v1 sync endpoints use, so a tenant on
// api.us2.sumologic.com lands on api.us2.sumologic.com/api/v1/scim/v2.
func sumoLogicSCIMBaseURL(cfg Config) string {
	dep := strings.ToLower(strings.TrimSpace(cfg.Deployment))
	if dep == "" {
		dep = "us2"
	}
	if dep == "us1" {
		return "https://api.sumologic.com/api/v1/scim/v2"
	}
	return "https://api." + dep + ".sumologic.com/api/v1/scim/v2"
}

// scimConfig adapts per-tenant config + secrets into the
// scim_base_url + scim_auth_header pair. base URL is overridable for
// self-hosted SCIM proxies and tests via the `scim_base_url` *config*
// key (NOT secret — endpoints are configuration, not credentials,
// matching the convention used by aws/datadog/zendesk/knowbe4/
// pagerduty/tailscale/launchdarkly). The auth header is always
// `Bearer {scim_token}` where `scim_token` lives in secrets.
func (c *SumoLogicAccessConnector) scimConfig(cfg Config, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	token, _ := secretsRaw["scim_token"].(string)
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil, errors.New("sumo_logic: scim_token is required for SCIM provisioning")
	}
	base := sumoLogicSCIMBaseURL(cfg)
	if override, ok := configRaw["scim_base_url"].(string); ok {
		if v := strings.TrimSpace(override); v != "" {
			base = strings.TrimRight(v, "/")
		}
	}
	if c.urlOverride != "" {
		base = strings.TrimRight(c.urlOverride, "/") + "/api/v1/scim/v2"
	}
	return map[string]interface{}{
			"scim_base_url": base,
		}, map[string]interface{}{
			"scim_auth_header": "Bearer " + token,
		}, nil
}

func (c *SumoLogicAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
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

func (c *SumoLogicAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
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

func (c *SumoLogicAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
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

var _ access.SCIMProvisioner = (*SumoLogicAccessConnector)(nil)
