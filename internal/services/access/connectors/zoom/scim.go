// Package zoom — SCIM v2.0 outbound provisioning composition.
//
// Zoom exposes a SCIM 2.0 endpoint at `{base_url}/scim2/Users` (and
// /Groups). The connector first mints a server-to-server access
// token via the OAuth client_credentials grant, then drives the
// generic SCIMClient with `Authorization: Bearer {access_token}`.
package zoom

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

// scimConfig adapts the connector's (configRaw, secretsRaw) pair
// into the SCIMClient's `scim_base_url` + `scim_auth_header` shape.
// Zoom requires an OAuth access token, so the SCIM adapter mints a
// fresh token via the existing accessToken cache.
func (c *ZoomAccessConnector) scimConfig(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, nil, err
	}
	token, err := c.accessToken(ctx, cfg, secrets)
	if err != nil {
		return nil, nil, err
	}
	// Zoom's SCIM 2.0 endpoint lives at the host root (`/scim2/Users`),
	// not under the REST API's `/v2` prefix. Strip the trailing `/v2`
	// from the REST base before appending `/scim2`. urlOverride paths
	// in tests have no `/v2` suffix, so TrimSuffix is a no-op there.
	scimBaseURL := strings.TrimSuffix(c.baseURL(), "/v2") + "/scim2"
	scimCfg := map[string]interface{}{
		"scim_base_url": scimBaseURL,
	}
	scimSecrets := map[string]interface{}{
		"scim_auth_header": "Bearer " + strings.TrimPrefix(strings.TrimSpace(token), "Bearer "),
	}
	return scimCfg, scimSecrets, nil
}

// PushSCIMUser satisfies access.SCIMProvisioner.
func (c *ZoomAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
	scimCfg, scimSecrets, err := c.scimConfig(ctx, configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMUser(ctx, scimCfg, scimSecrets, user)
}

// PushSCIMGroup satisfies access.SCIMProvisioner.
func (c *ZoomAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
	scimCfg, scimSecrets, err := c.scimConfig(ctx, configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMGroup(ctx, scimCfg, scimSecrets, group)
}

// DeleteSCIMResource satisfies access.SCIMProvisioner.
func (c *ZoomAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
	scimCfg, scimSecrets, err := c.scimConfig(ctx, configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, resourceType, externalID)
}

var _ access.SCIMProvisioner = (*ZoomAccessConnector)(nil)
