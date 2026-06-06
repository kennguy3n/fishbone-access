// Package grafana — SCIM v2.0 outbound provisioning composition.
//
// Grafana Cloud exposes a SCIM 2.0 endpoint on each stack at
// {stack-url}/apis/iam.grafana.app/v0alpha1/namespaces/stack-{stack-id}/scim/v2.
// Because the path includes the per-tenant stack identifier, this
// connector derives the SCIM base URL from the connector's existing
// Config.BaseURL (the stack URL) and requires a `scim_base_url`
// override OR a `scim_path` suffix in the SCIM secrets so operators
// don't have to hard-code the namespace into source. Grafana SCIM
// uses a dedicated bearer token (a service-account token with the
// scim:provisioning scope) surfaced as the `scim_token` secret.
package grafana

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
// scim_base_url + scim_auth_header pair. base URL must be supplied
// because Grafana's SCIM path varies per stack — either explicitly
// via the `scim_base_url` *config* key OR derived from the
// connector's existing Config.BaseURL + `scim_path` *config* key. The
// auth header is always `Bearer {scim_token}` where `scim_token`
// lives in secrets. URL endpoints are configuration, not credentials,
// matching the convention used by aws/datadog/zendesk/knowbe4/
// pagerduty/tailscale/launchdarkly.
func (c *GrafanaAccessConnector) scimConfig(cfg Config, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	token, _ := secretsRaw["scim_token"].(string)
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil, errors.New("grafana: scim_token is required for SCIM provisioning")
	}
	base := ""
	if override, ok := configRaw["scim_base_url"].(string); ok {
		base = strings.TrimRight(strings.TrimSpace(override), "/")
	}
	if base == "" {
		// Fall back to connector base + scim_path suffix (must be set
		// explicitly because Grafana's SCIM path includes the per-stack
		// namespace identifier — we can't synthesise it).
		stack := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
		suffix, _ := configRaw["scim_path"].(string)
		suffix = strings.TrimSpace(suffix)
		if stack != "" && suffix != "" {
			base = stack + "/" + strings.TrimLeft(suffix, "/")
		}
	}
	if c.urlOverride != "" {
		// Test/override path — pretend the override is a SCIM root.
		base = strings.TrimRight(c.urlOverride, "/")
	}
	if base == "" {
		return nil, nil, errors.New("grafana: scim_base_url (or config.base_url + scim_path) is required for SCIM provisioning")
	}
	return map[string]interface{}{
			"scim_base_url": base,
		}, map[string]interface{}{
			"scim_auth_header": "Bearer " + token,
		}, nil
}

func (c *GrafanaAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
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

func (c *GrafanaAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
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

func (c *GrafanaAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
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

var _ access.SCIMProvisioner = (*GrafanaAccessConnector)(nil)
