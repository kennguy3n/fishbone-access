// Package launchdarkly — SCIM v2.0 outbound provisioning composition.
//
// LaunchDarkly exposes a SCIM 2.0 endpoint at
// https://app.launchdarkly.com/trust/scim/v2/. The endpoint is gated
// to LaunchDarkly accounts with SSO + SCIM provisioning enabled and
// uses a dedicated SCIM bearer token minted from the LaunchDarkly UI
// (Account Settings → Authorization → SCIM). We surface that token
// as the `scim_token` secret and require it explicitly; the regular
// `api_key` used by the rest of this connector is NOT valid against
// the SCIM endpoint.
package launchdarkly

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const launchdarklySCIMDefaultBaseURL = "https://app.launchdarkly.com/trust/scim/v2"

// scimClient holds the process-wide SCIMClient behind an atomic pointer so
// both the lazy initialization and SetSCIMClientForTest are goroutine-safe,
// letting SCIM tests run with t.Parallel() without data races.
var scimClient atomic.Pointer[access.SCIMClient]

func scim() *access.SCIMClient {
	if c := scimClient.Load(); c != nil {
		return c
	}
	c := access.NewSCIMClient()
	if scimClient.CompareAndSwap(nil, c) {
		return c
	}
	return scimClient.Load()
}

// SetSCIMClientForTest swaps the package-level SCIMClient and returns
// the previous one so tests can restore it on cleanup.
func SetSCIMClientForTest(c *access.SCIMClient) *access.SCIMClient {
	prev := scim()
	scimClient.Store(c)
	return prev
}

// scimConfig adapts LaunchDarkly's per-tenant config + secrets into
// the `scim_base_url` + `scim_auth_header` pair the shared SCIMClient
// expects. The base URL is overridable for self-hosted SCIM proxies
// and for tests via the `scim_base_url` *config* key (NOT secret —
// endpoints are configuration, not credentials, matching the
// convention used by aws/datadog/zendesk/knowbe4/pagerduty/tailscale).
// The auth header is always `Bearer {scim_token}` where `scim_token`
// lives in secrets.
func (c *LaunchDarklyAccessConnector) scimConfig(configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	token, _ := secretsRaw["scim_token"].(string)
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil, errors.New("launchdarkly: scim_token is required for SCIM provisioning")
	}
	base := launchdarklySCIMDefaultBaseURL
	if override, ok := configRaw["scim_base_url"].(string); ok {
		if v := strings.TrimSpace(override); v != "" {
			base = strings.TrimRight(v, "/")
		}
	}
	if c.urlOverride != "" {
		base = strings.TrimRight(c.urlOverride, "/") + "/trust/scim/v2"
	}
	return map[string]interface{}{
			"scim_base_url": base,
		}, map[string]interface{}{
			"scim_auth_header": "Bearer " + token,
		}, nil
}

func (c *LaunchDarklyAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
	if _, _, err := c.decodeBoth(configRaw, secretsRaw); err != nil {
		return err
	}
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMUser(ctx, scimCfg, scimSecrets, user)
}

func (c *LaunchDarklyAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
	if _, _, err := c.decodeBoth(configRaw, secretsRaw); err != nil {
		return err
	}
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMGroup(ctx, scimCfg, scimSecrets, group)
}

func (c *LaunchDarklyAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
	if _, _, err := c.decodeBoth(configRaw, secretsRaw); err != nil {
		return err
	}
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, resourceType, externalID)
}

var _ access.SCIMProvisioner = (*LaunchDarklyAccessConnector)(nil)
