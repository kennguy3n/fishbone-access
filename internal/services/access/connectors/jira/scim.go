// Package jira — SCIM v2.0 outbound provisioning composition.
//
// Atlassian publishes a SCIM 2.0 endpoint for organization-level
// directories at `https://api.atlassian.com/scim/directory/{directoryId}/Users`
// (and /Groups). The SCIM directory_id and bearer token are issued
// separately from the per-site cloud API token, so the adapter reads
// them from dedicated config/secret keys.
package jira

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

// scimGatewayBase is the Atlassian SCIM control-plane host. Tests
// override this via the connector's urlOverride field.
const scimGatewayBase = "https://api.atlassian.com"

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
//
// Required keys:
//   - configRaw["scim_directory_id"]: Atlassian SCIM directory UUID
//   - secretsRaw["scim_token"]: Bearer token issued by Atlassian Access
func (c *JiraAccessConnector) scimConfig(configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	directoryID, _ := configRaw["scim_directory_id"].(string)
	directoryID = strings.TrimSpace(directoryID)
	if directoryID == "" {
		return nil, nil, fmt.Errorf("jira: scim: scim_directory_id is required")
	}
	token, _ := secretsRaw["scim_token"].(string)
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil, fmt.Errorf("jira: scim: scim_token is required")
	}
	base := scimGatewayBase
	if c.urlOverride != "" {
		base = strings.TrimRight(c.urlOverride, "/")
	}
	scimBaseURL := base + "/scim/directory/" + directoryID
	scimCfg := map[string]interface{}{
		"scim_base_url": scimBaseURL,
	}
	scimSecrets := map[string]interface{}{
		"scim_auth_header": "Bearer " + strings.TrimPrefix(token, "Bearer "),
	}
	return scimCfg, scimSecrets, nil
}

// PushSCIMUser satisfies access.SCIMProvisioner.
func (c *JiraAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMUser(ctx, scimCfg, scimSecrets, user)
}

// PushSCIMGroup satisfies access.SCIMProvisioner.
func (c *JiraAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMGroup(ctx, scimCfg, scimSecrets, group)
}

// DeleteSCIMResource satisfies access.SCIMProvisioner.
func (c *JiraAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, resourceType, externalID)
}

var _ access.SCIMProvisioner = (*JiraAccessConnector)(nil)
