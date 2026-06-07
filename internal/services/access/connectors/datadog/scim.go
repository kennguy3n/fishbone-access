// Package datadog — SCIM v2.0 outbound provisioning composition.
//
// Datadog Enterprise exposes a SCIM 2.0 endpoint at
// `https://api.{site}/api/v2/scim/Users` and `/Groups`. The shared
// SCIMClient drives it with a Bearer token sourced from the
// application key (the same value used for the v2 user API), per
// https://docs.datadoghq.com/account_management/scim/.
package datadog

import (
	"context"
	"strings"
	"sync"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

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
// the previous one so the test can restore it on cleanup.
func SetSCIMClientForTest(c *access.SCIMClient) *access.SCIMClient {
	prev := scim()
	scimClientMu.Lock()
	scimClient = c
	scimClientMu.Unlock()
	return prev
}

// scimConfig adapts the connector's (configRaw, secretsRaw) pair into
// the SCIMClient's `scim_base_url` + `scim_auth_header` shape.
//
// Datadog uses the same DD-API-KEY + DD-APPLICATION-KEY headers it
// uses for the REST API, but the SCIM v2 client expects a single
// `Authorization` header. Datadog accepts `Bearer {application_key}`
// on the SCIM endpoint; the legacy DD-* headers are mirrored in the
// internal/services/access SCIMClient so they remain available for
// the v2 Roles API. Tests inject the application_key as the SCIM
// bearer to mirror production.
func (c *DatadogAccessConnector) scimConfig(configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, nil, err
	}
	scimBaseURL := c.baseURL(cfg) + "/api/v2/scim"
	scimCfg := map[string]interface{}{
		"scim_base_url": scimBaseURL,
	}
	scimSecrets := map[string]interface{}{
		"scim_auth_header": "Bearer " + strings.TrimPrefix(strings.TrimSpace(secrets.ApplicationKey), "Bearer "),
	}
	return scimCfg, scimSecrets, nil
}

// PushSCIMUser satisfies access.SCIMProvisioner.
func (c *DatadogAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMUser(ctx, scimCfg, scimSecrets, user)
}

// PushSCIMGroup satisfies access.SCIMProvisioner.
func (c *DatadogAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMGroup(ctx, scimCfg, scimSecrets, group)
}

// DeleteSCIMResource satisfies access.SCIMProvisioner.
func (c *DatadogAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, resourceType, externalID)
}

var _ access.SCIMProvisioner = (*DatadogAccessConnector)(nil)
