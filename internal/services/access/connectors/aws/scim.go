// Package aws — SCIM v2.0 outbound provisioning composition.
//
// AWS IAM Identity Center exposes a SCIM 2.0 endpoint at
// `https://scim.{region}.amazonaws.com/{tenantId}/scim/v2/Users`
// (and /Groups). The endpoint uses a dedicated Bearer token issued
// from the Identity Center console — it is not derived from the IAM
// access key the rest of the connector uses. The SCIM adapter
// therefore reads two optional keys directly from the configRaw /
// secretsRaw maps:
//
//   - configRaw["scim_base_url"] (required) — the full SCIM v2 base
//     URL copied from the Identity Center console.
//   - secretsRaw["scim_bearer_token"] (required) — the dedicated
//     Identity Center SCIM bearer token.
//
// Tests can also override the endpoint via urlOverride on the
// connector (see scim_test.go), in which case scim_base_url falls
// back to `{urlOverride}/scim/v2`.
package aws

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
// the previous one so the test can restore it on cleanup.
func SetSCIMClientForTest(c *access.SCIMClient) *access.SCIMClient {
	prev := scim()
	scimClient = c
	return prev
}

// scimConfig adapts the connector's (configRaw, secretsRaw) pair into
// the SCIMClient's `scim_base_url` + `scim_auth_header` shape.
func (c *AWSAccessConnector) scimConfig(configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	if configRaw == nil {
		return nil, nil, errors.New("aws: config is nil")
	}
	if secretsRaw == nil {
		return nil, nil, errors.New("aws: secrets is nil")
	}
	scimBaseURL, _ := configRaw["scim_base_url"].(string)
	scimBaseURL = strings.TrimSpace(scimBaseURL)
	if scimBaseURL == "" {
		if c.urlOverride != "" {
			scimBaseURL = strings.TrimRight(c.urlOverride, "/") + "/scim/v2"
		} else {
			return nil, nil, errors.New("aws: scim_base_url is required")
		}
	}
	token, _ := secretsRaw["scim_bearer_token"].(string)
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil, errors.New("aws: scim_bearer_token is required")
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
func (c *AWSAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMUser(ctx, scimCfg, scimSecrets, user)
}

// PushSCIMGroup satisfies access.SCIMProvisioner.
func (c *AWSAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMGroup(ctx, scimCfg, scimSecrets, group)
}

// DeleteSCIMResource satisfies access.SCIMProvisioner.
func (c *AWSAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, resourceType, externalID)
}

var _ access.SCIMProvisioner = (*AWSAccessConnector)(nil)
