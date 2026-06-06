// Package zendesk — SCIM v2.0 outbound provisioning composition.
//
// Zendesk exposes a SCIM 2.0 endpoint under the standard REST API
// prefix: `{subdomain}.zendesk.com/api/v2/scim/v2/Users` (and
// /Groups). The shared SCIMClient drives it with Basic auth derived
// from the connector's email + api_token secret pair (Zendesk's
// standard auth scheme).
package zendesk

import (
	"context"
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
// the previous one so the test can restore it on cleanup.
func SetSCIMClientForTest(c *access.SCIMClient) *access.SCIMClient {
	prev := scim()
	scimClient = c
	return prev
}

// scimConfig adapts the connector's (configRaw, secretsRaw) pair into
// the SCIMClient's `scim_base_url` + `scim_auth_header` shape.
func (c *ZendeskAccessConnector) scimConfig(configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, nil, err
	}
	// Zendesk's SCIM endpoint sits under the same `/api/v2` REST API
	// prefix as the rest of the connector's calls — see
	// https://developer.zendesk.com/api-reference/ticketing/users/scim/.
	scimBaseURL := c.baseURL(cfg) + "/api/v2/scim/v2"
	scimCfg := map[string]interface{}{
		"scim_base_url": scimBaseURL,
	}
	scimSecrets := map[string]interface{}{
		"scim_auth_header": basicAuthHeader(secrets.Email, secrets.APIToken),
	}
	return scimCfg, scimSecrets, nil
}

// PushSCIMUser satisfies access.SCIMProvisioner.
func (c *ZendeskAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMUser(ctx, scimCfg, scimSecrets, user)
}

// PushSCIMGroup satisfies access.SCIMProvisioner.
func (c *ZendeskAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMGroup(ctx, scimCfg, scimSecrets, group)
}

// DeleteSCIMResource satisfies access.SCIMProvisioner.
func (c *ZendeskAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, resourceType, externalID)
}

var _ access.SCIMProvisioner = (*ZendeskAccessConnector)(nil)
