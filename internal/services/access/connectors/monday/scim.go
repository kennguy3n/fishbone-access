// Package monday — SCIM v2.0 outbound provisioning composition.
//
// Monday.com exposes a SCIM 2.0 endpoint at
// https://api.monday.com/scim/v2/ on Enterprise plans with SCIM
// provisioning enabled. The endpoint requires a dedicated SCIM
// bearer token minted from Admin → Security → SCIM provisioning;
// it is distinct from the regular `api_token` used for GraphQL
// calls and is surfaced as the `scim_token` secret.
package monday

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const mondaySCIMDefaultBaseURL = "https://api.monday.com/scim/v2"

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

// scimConfig adapts Monday's per-tenant config + secrets into the
// `scim_base_url` + `scim_auth_header` pair the shared SCIMClient
// expects. The base URL is overridable for self-hosted SCIM proxies
// and for tests; the auth header is always `Bearer {scim_token}`.
//
// The `scim_base_url` override is read from configRaw (NOT
// secretsRaw): endpoint URLs are non-sensitive routing data and
// belong with the rest of the connector configuration, matching
// the established convention across aws / datadog / launchdarkly /
// pagerduty / zendesk and every other SCIM-enabled connector.
// Reading it from secretsRaw silently ignored the documented
// config key for operators who put it in their plain-text config.
func (c *MondayAccessConnector) scimConfig(configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	token, _ := secretsRaw["scim_token"].(string)
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil, errors.New("monday: scim_token is required for SCIM provisioning (Enterprise plan)")
	}
	base := mondaySCIMDefaultBaseURL
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
			"scim_auth_header": "Bearer " + token,
		}, nil
}

func (c *MondayAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
	if _, _, err := c.decodeBoth(configRaw, secretsRaw); err != nil {
		return err
	}
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMUser(ctx, scimCfg, scimSecrets, user)
}

func (c *MondayAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
	if _, _, err := c.decodeBoth(configRaw, secretsRaw); err != nil {
		return err
	}
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMGroup(ctx, scimCfg, scimSecrets, group)
}

func (c *MondayAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
	if _, _, err := c.decodeBoth(configRaw, secretsRaw); err != nil {
		return err
	}
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, resourceType, externalID)
}

var _ access.SCIMProvisioner = (*MondayAccessConnector)(nil)
