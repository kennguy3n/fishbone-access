// Package cloudflare — SCIM v2.0 outbound provisioning composition.
//
// Cloudflare Access provisions identities via an IdP-specific SCIM
// endpoint that lives under the customer's Access team domain:
//
//	https://{team_domain}.cloudflareaccess.com/cdn-cgi/access/sso/scim/{idp_id}/scim/v2
//
// Because the path includes the per-IdP identifier (created when the
// operator configures an Access identity provider with SCIM
// provisioning enabled), this connector requires operators to supply
// the full SCIM base URL explicitly via the `scim_base_url` *config*
// key — we cannot synthesise the {idp_id} segment automatically. URL
// endpoints are configuration, not credentials, matching the
// convention used by aws/datadog/zendesk/knowbe4/pagerduty/tailscale/
// launchdarkly/sumo_logic/grafana/rippling/docusign. SCIM uses a
// dedicated bearer token minted in the Access IdP configuration page
// surfaced as the `scim_token` *secret*.
package cloudflare

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

// scimConfig adapts per-tenant config + secrets into the
// scim_base_url + scim_auth_header pair. The base URL must be
// supplied explicitly via the `scim_base_url` *config* key because
// Cloudflare's SCIM endpoint includes the per-IdP identifier minted
// when SCIM provisioning is enabled for an Access IdP integration.
// The auth header is always `Bearer {scim_token}` where `scim_token`
// lives in secrets.
func (c *CloudflareAccessConnector) scimConfig(_ Config, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	token, _ := secretsRaw["scim_token"].(string)
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil, errors.New("cloudflare: scim_token is required for SCIM provisioning")
	}
	base, _ := configRaw["scim_base_url"].(string)
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if c.urlOverride != "" {
		base = strings.TrimRight(c.urlOverride, "/")
	}
	if base == "" {
		return nil, nil, errors.New("cloudflare: scim_base_url is required for SCIM provisioning " +
			"(set to the IdP-specific cloudflareaccess.com SCIM URL)")
	}
	return map[string]interface{}{
			"scim_base_url": base,
		}, map[string]interface{}{
			"scim_auth_header": "Bearer " + token,
		}, nil
}

func (c *CloudflareAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
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

func (c *CloudflareAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
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

func (c *CloudflareAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
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

var _ access.SCIMProvisioner = (*CloudflareAccessConnector)(nil)
