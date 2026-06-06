// Package microsoft — SCIM v2.0 outbound provisioning composition.
//
// Microsoft Entra ID exposes a SCIM v2.0 surface via Graph at
// https://graph.microsoft.com/v1.0 for tenants that have published
// a SCIM provisioning endpoint on their Entra app. The
// access-platform's generic access.SCIMClient handles the wire
// plumbing; this file composes the client with the microsoft
// connector's config + secrets so the connector satisfies the
// access.SCIMProvisioner optional interface.
//
// Auth: Bearer token from the existing OAuth2 client-credentials
// flow (config.tenant_id + config.client_id + secrets.client_secret).
package microsoft

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// scimClient is the package-level SCIMClient instance used by the
// SCIM* methods on M365AccessConnector. Initialised on first use so
// the package has no init-order dependency on the access package.
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

// scimConfig adapts the microsoft connector's (configRaw, secretsRaw)
// pair into the SCIMClient's config / secrets maps.
//
// The SCIM base URL defaults to https://graph.microsoft.com/v1.0;
// tests redirect it via scimURLOverride. The Authorization header
// is "Bearer {token}" where token is acquired via the
// client-credentials flow (or a static value injected by tests via
// scimBearerTokenFor).
func (c *M365AccessConnector) scimConfig(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, nil, err
	}
	scimBaseURL := graphBaseURL
	if c.scimURLOverride != "" {
		scimBaseURL = strings.TrimRight(c.scimURLOverride, "/")
	}
	token, err := c.scimBearerToken(ctx, cfg, secrets)
	if err != nil {
		return nil, nil, fmt.Errorf("microsoft: scim: acquire token: %w", err)
	}
	scimCfg := map[string]interface{}{
		"scim_base_url": scimBaseURL,
	}
	scimSecrets := map[string]interface{}{
		"scim_auth_header": "Bearer " + token,
	}
	return scimCfg, scimSecrets, nil
}

// scimBearerToken returns the Bearer token used to authenticate SCIM
// requests. Production paths run the client-credentials flow; tests
// set scimBearerTokenFor to bypass OAuth2.
func (c *M365AccessConnector) scimBearerToken(ctx context.Context, cfg Config, secrets Secrets) (string, error) {
	if c.scimBearerTokenFor != nil {
		return c.scimBearerTokenFor(ctx, cfg, secrets)
	}
	tok, err := newClientCredentialsConfig(cfg, secrets).Token(ctx)
	if err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}

// PushSCIMUser satisfies access.SCIMProvisioner.
func (c *M365AccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
	scimCfg, scimSecrets, err := c.scimConfig(ctx, configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMUser(ctx, scimCfg, scimSecrets, user)
}

// PushSCIMGroup satisfies access.SCIMProvisioner.
func (c *M365AccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
	scimCfg, scimSecrets, err := c.scimConfig(ctx, configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMGroup(ctx, scimCfg, scimSecrets, group)
}

// DeleteSCIMResource satisfies access.SCIMProvisioner. resourceType
// MUST be "Users" or "Groups" per RFC 7644 §3.4.1.
func (c *M365AccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
	scimCfg, scimSecrets, err := c.scimConfig(ctx, configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, resourceType, externalID)
}
