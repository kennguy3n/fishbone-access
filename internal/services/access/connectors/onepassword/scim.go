// Package onepassword — SCIM v2.0 outbound provisioning composition.
//
// 1Password's SCIM bridge speaks SCIM v2.0 natively at
// {scim_bridge_url}/scim/v2 (typically the bridge is hosted on a
// separate URL from the account URL — operators wire the bridge URL
// into the connector via the account_url field for now). The
// access-platform's generic access.SCIMClient handles the wire
// plumbing; this file composes the client with the 1Password
// connector's config + secrets so the connector satisfies the
// access.SCIMProvisioner optional interface.
package onepassword

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// scimClient is the package-level SCIMClient instance used by the
// SCIM* methods on OnePasswordAccessConnector. Initialised on first
// use so the package has no init-order dependency on the access
// package.
var (
	scimClientOnce sync.Once
	scimClient     *access.SCIMClient
)

// scim returns the lazily-constructed SCIMClient. Tests can override
// it via SetSCIMClientForTest.
func scim() *access.SCIMClient {
	scimClientOnce.Do(func() {
		scimClient = access.NewSCIMClient()
	})
	return scimClient
}

// SetSCIMClientForTest swaps the package-level SCIMClient. Intended
// for tests that need to point the SCIM dispatch at an
// httptest.Server. The previous client is returned so the test can
// restore it via t.Cleanup.
func SetSCIMClientForTest(c *access.SCIMClient) *access.SCIMClient {
	prev := scim()
	scimClient = c
	return prev
}

// scimConfig adapts the 1Password connector's (configRaw, secretsRaw)
// pair into the SCIMClient's config / secrets maps. The SCIM base
// URL is derived from account_url; the auth header is the bearer
// token (SCIM bridge or service account).
func (c *OnePasswordAccessConnector) scimConfig(configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, nil, err
	}
	base := cfg.normalisedAccountURL()
	if c.urlOverride != "" {
		base = strings.TrimRight(c.urlOverride, "/")
	}
	if base == "" {
		return nil, nil, fmt.Errorf("onepassword: scim: account_url is required")
	}
	scimBaseURL := base + "/scim/v2"
	scimCfg := map[string]interface{}{
		"scim_base_url": scimBaseURL,
	}
	scimSecrets := map[string]interface{}{
		"scim_auth_header": "Bearer " + secrets.bearerToken(),
	}
	return scimCfg, scimSecrets, nil
}

// PushSCIMUser satisfies access.SCIMProvisioner. Delegates to the
// shared SCIMClient against the 1Password SCIM bridge.
func (c *OnePasswordAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMUser(ctx, scimCfg, scimSecrets, user)
}

// PushSCIMGroup satisfies access.SCIMProvisioner. Delegates to the
// shared SCIMClient against the 1Password SCIM bridge.
func (c *OnePasswordAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMGroup(ctx, scimCfg, scimSecrets, group)
}

// DeleteSCIMResource satisfies access.SCIMProvisioner. Delegates to
// the shared SCIMClient. resourceType MUST be "Users" or "Groups"
// per RFC 7644 §3.4.1.
func (c *OnePasswordAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, resourceType, externalID)
}
