// Package lastpass — SCIM v2.0 outbound provisioning composition.
//
// LastPass Enterprise exposes a SCIM-compatible endpoint at
// https://lastpass.com/enterpriseapi.php for Tier 1 SCIM
// provisioning. The access-platform's generic SCIMClient handles
// the wire plumbing.
//
// Auth: API key from secrets.api_key sent as
// "Authorization: Basic {b64(account_number:api_key)}" in the
// LastPass-recommended header style; some operators paste a
// pre-baked Bearer token, which is also tolerated.
package lastpass

import (
	"context"
	"encoding/base64"
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

// scimConfig adapts the lastpass connector's config + secrets into
// the SCIMClient's config / secrets maps.
func (c *LastPassAccessConnector) scimConfig(configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, nil, err
	}
	scimBaseURL := defaultEndpoint
	if c.urlOverride != "" {
		scimBaseURL = strings.TrimRight(c.urlOverride, "/")
	}

	apiKey, _ := secretsRaw["api_key"].(string)
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return nil, nil, fmt.Errorf("lastpass: scim: api_key is required")
	}
	authValue := "Basic " + base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(cfg.AccountNumber)+":"+apiKey))

	scimCfg := map[string]interface{}{
		"scim_base_url": scimBaseURL,
	}
	scimSecrets := map[string]interface{}{
		"scim_auth_header": authValue,
	}
	return scimCfg, scimSecrets, nil
}

// PushSCIMUser satisfies access.SCIMProvisioner.
func (c *LastPassAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMUser(ctx, scimCfg, scimSecrets, user)
}

// PushSCIMGroup satisfies access.SCIMProvisioner.
func (c *LastPassAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMGroup(ctx, scimCfg, scimSecrets, group)
}

// DeleteSCIMResource satisfies access.SCIMProvisioner.
func (c *LastPassAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, resourceType, externalID)
}

var _ access.SCIMProvisioner = (*LastPassAccessConnector)(nil)
