// Package docusign — SCIM v2.0 outbound provisioning composition.
//
// DocuSign exposes a SCIM 2.0 endpoint via DocuSign Admin at
// https://account.docusign.com/scim/v2/ (production) and
// https://account-d.docusign.com/scim/v2/ (demo). The endpoint is
// gated to DocuSign organisations that have enabled SCIM
// provisioning. SCIM uses a dedicated organisation admin access
// token distinct from the eSignature REST API token used for
// /restapi/v2.1/* sync calls; we surface that token as the
// `scim_token` secret.
//
// The environment (production vs demo) is derived from the same
// AccountEnvironment field already used to select the eSignature
// REST host so tenants don't need to configure SCIM separately.
package docusign

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

// docusignSCIMBaseURL chooses between the demo and production SCIM
// hosts based on AccountEnvironment.
func docusignSCIMBaseURL(cfg Config) string {
	if strings.EqualFold(strings.TrimSpace(cfg.AccountEnvironment), "demo") {
		return "https://account-d.docusign.com/scim/v2"
	}
	return "https://account.docusign.com/scim/v2"
}

// scimConfig adapts per-tenant config + secrets into the
// scim_base_url + scim_auth_header pair. base URL is overridable for
// self-hosted SCIM proxies and tests via the `scim_base_url` *config*
// key (NOT secret — endpoints are configuration, not credentials,
// matching the convention used by aws/datadog/zendesk/knowbe4/
// pagerduty/tailscale/launchdarkly). The auth header is always
// `Bearer {scim_token}` where `scim_token` lives in secrets.
func (c *DocuSignAccessConnector) scimConfig(cfg Config, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	token, _ := secretsRaw["scim_token"].(string)
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil, errors.New("docusign: scim_token is required for SCIM provisioning")
	}
	base := docusignSCIMBaseURL(cfg)
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

func (c *DocuSignAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
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

func (c *DocuSignAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
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

func (c *DocuSignAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
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

var _ access.SCIMProvisioner = (*DocuSignAccessConnector)(nil)
