// Package auth0 — SCIM v2.0 outbound provisioning composition.
//
// Auth0 exposes the Management API at https://{auth0_domain}/api/v2;
// the access-platform's generic SCIMClient runs against it via a
// Bearer token from secrets.management_api_token.
//
// Auth: Bearer token from secrets.management_api_token (a long-lived
// Management API token operators paste during connector setup).
package auth0

import (
	"context"
	"fmt"
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

// scimConfig adapts the Auth0 connector's (configRaw, secretsRaw)
// pair into the SCIMClient's config / secrets maps.
func (c *Auth0AccessConnector) scimConfig(configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, nil, err
	}
	domain := cfg.normalised()
	if domain == "" {
		return nil, nil, fmt.Errorf("auth0: scim: domain is required")
	}
	scimBaseURL := "https://" + domain + "/api/v2"
	if c.urlOverride != "" {
		scimBaseURL = strings.TrimRight(c.urlOverride, "/") + "/api/v2"
	}

	token, _ := secretsRaw["management_api_token"].(string)
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil, fmt.Errorf("auth0: scim: management_api_token is required")
	}
	scimCfg := map[string]interface{}{
		"scim_base_url": scimBaseURL,
	}
	scimSecrets := map[string]interface{}{
		"scim_auth_header": "Bearer " + strings.TrimPrefix(token, "Bearer "),
	}
	return scimCfg, scimSecrets, nil
}

// PushSCIMUser satisfies access.SCIMProvisioner.
func (c *Auth0AccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMUser(ctx, scimCfg, scimSecrets, user)
}

// PushSCIMGroup satisfies access.SCIMProvisioner.
func (c *Auth0AccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMGroup(ctx, scimCfg, scimSecrets, group)
}

// DeleteSCIMResource satisfies access.SCIMProvisioner.
func (c *Auth0AccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, resourceType, externalID)
}
