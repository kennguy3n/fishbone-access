// Package rippling — SCIM v2.0 outbound provisioning composition.
//
// Rippling exposes a SCIM 2.0 endpoint at
// https://api.rippling.com/platform/api/scim/v2/. The endpoint is
// gated to Rippling accounts with their SCIM provisioning module
// enabled. SCIM uses a dedicated bearer token distinct from the
// platform API key used for /platform/api/* sync calls; we surface
// that token as the `scim_token` secret.
package rippling

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const ripplingSCIMDefaultBaseURL = "https://api.rippling.com/platform/api/scim/v2"

var (
	scimClientOnce sync.Once
	scimClientMu   sync.RWMutex
	scimClient     *access.SCIMClient
)

func scim() *access.SCIMClient {
	scimClientOnce.Do(func() {
		scimClientMu.Lock()
		scimClient = access.NewSCIMClient()
		scimClientMu.Unlock()
	})
	scimClientMu.RLock()
	defer scimClientMu.RUnlock()
	return scimClient
}

// SetSCIMClientForTest swaps the package-level SCIMClient and returns
// the previous one so tests can restore it on cleanup.
func SetSCIMClientForTest(c *access.SCIMClient) *access.SCIMClient {
	prev := scim()
	scimClientMu.Lock()
	scimClient = c
	scimClientMu.Unlock()
	return prev
}

// scimConfig adapts per-tenant config + secrets into the
// scim_base_url + scim_auth_header pair. base URL is overridable for
// self-hosted SCIM proxies and tests via the `scim_base_url` *config*
// key (NOT secret — endpoints are configuration, not credentials,
// matching the convention used by aws/datadog/zendesk/knowbe4/
// pagerduty/tailscale/launchdarkly). The auth header is always
// `Bearer {scim_token}` where `scim_token` lives in secrets.
func (c *RipplingAccessConnector) scimConfig(_ Config, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	token, _ := secretsRaw["scim_token"].(string)
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil, errors.New("rippling: scim_token is required for SCIM provisioning")
	}
	base := ripplingSCIMDefaultBaseURL
	if override, ok := configRaw["scim_base_url"].(string); ok {
		if v := strings.TrimSpace(override); v != "" {
			base = strings.TrimRight(v, "/")
		}
	}
	if c.urlOverride != "" {
		base = strings.TrimRight(c.urlOverride, "/") + "/platform/api/scim/v2"
	}
	return map[string]interface{}{
			"scim_base_url": base,
		}, map[string]interface{}{
			"scim_auth_header": "Bearer " + token,
		}, nil
}

func (c *RipplingAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
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

func (c *RipplingAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
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

func (c *RipplingAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
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

var _ access.SCIMProvisioner = (*RipplingAccessConnector)(nil)
