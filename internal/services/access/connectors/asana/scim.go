// Package asana — SCIM v2.0 outbound provisioning composition.
//
// Asana Enterprise exposes a SCIM 2.0 endpoint at `{base}/scim/Users`
// (and /Groups). The shared SCIMClient drives it with a Bearer token
// sourced from the connector's access_token secret.
package asana

import (
	"context"
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
// the previous one so the test can restore it on cleanup.
func SetSCIMClientForTest(c *access.SCIMClient) *access.SCIMClient {
	prev := scim()
	scimClient = c
	return prev
}

// scimConfig adapts the connector's (configRaw, secretsRaw) pair into
// the SCIMClient's `scim_base_url` + `scim_auth_header` shape.
func (c *AsanaAccessConnector) scimConfig(configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, nil, err
	}
	scimBaseURL := c.baseURL() + "/scim"
	scimCfg := map[string]interface{}{
		"scim_base_url": scimBaseURL,
	}
	scimSecrets := map[string]interface{}{
		"scim_auth_header": "Bearer " + strings.TrimPrefix(strings.TrimSpace(secrets.AccessToken), "Bearer "),
	}
	return scimCfg, scimSecrets, nil
}

// PushSCIMUser satisfies access.SCIMProvisioner.
func (c *AsanaAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMUser(ctx, scimCfg, scimSecrets, user)
}

// PushSCIMGroup satisfies access.SCIMProvisioner.
func (c *AsanaAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMGroup(ctx, scimCfg, scimSecrets, group)
}

// DeleteSCIMResource satisfies access.SCIMProvisioner.
func (c *AsanaAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, resourceType, externalID)
}

var _ access.SCIMProvisioner = (*AsanaAccessConnector)(nil)
