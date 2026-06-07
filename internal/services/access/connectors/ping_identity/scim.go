// Package ping_identity — SCIM v2.0 outbound provisioning composition.
//
// PingOne exposes SCIM-shaped resources at
// https://api.pingone.{region}/v1/environments/{env_id}; the
// access-platform's generic SCIMClient runs against this surface
// per the "PingOne SCIM v2" provisioning surface.
//
// Auth: Bearer token from secrets.api_key. Operators paste either a
// raw token or one already prefixed with "Bearer ".
package ping_identity

import (
	"context"
	"fmt"
	"net/url"
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

// SetSCIMClientForTest swaps the package-level SCIMClient.
func SetSCIMClientForTest(c *access.SCIMClient) *access.SCIMClient {
	prev := scim()
	scimClient = c
	return prev
}

// scimConfig adapts the ping_identity connector's config + secrets
// into the SCIMClient's config / secrets maps. Regional routing
// reuses regionAPIHost.
func (c *PingIdentityAccessConnector) scimConfig(configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, nil, err
	}

	host, _ := regionAPIHost(cfg.Region)
	scimBaseURL := "https://" + host + "/v1/environments/" + url.PathEscape(cfg.EnvironmentID)
	if c.urlOverride != "" {
		scimBaseURL = strings.TrimRight(c.urlOverride, "/") + "/v1/environments/" + url.PathEscape(cfg.EnvironmentID)
	}

	apiKey, _ := secretsRaw["api_key"].(string)
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return nil, nil, fmt.Errorf("ping_identity: scim: api_key is required")
	}

	scimCfg := map[string]interface{}{
		"scim_base_url": scimBaseURL,
	}
	scimSecrets := map[string]interface{}{
		"scim_auth_header": "Bearer " + strings.TrimPrefix(apiKey, "Bearer "),
	}
	return scimCfg, scimSecrets, nil
}

// PushSCIMUser satisfies access.SCIMProvisioner.
func (c *PingIdentityAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMUser(ctx, scimCfg, scimSecrets, user)
}

// PushSCIMGroup satisfies access.SCIMProvisioner.
func (c *PingIdentityAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMGroup(ctx, scimCfg, scimSecrets, group)
}

// DeleteSCIMResource satisfies access.SCIMProvisioner.
func (c *PingIdentityAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, resourceType, externalID)
}
