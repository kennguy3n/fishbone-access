// Package okta — SCIM v2.0 outbound provisioning composition.
//
// Okta exposes a SCIM v2.0 endpoint at {okta_domain}/api/scim/v2 (the
// "Custom SCIM 2.0" provisioning surface) per
// https://developer.okta.com/docs/reference/scim/scim-20/. The
// access-platform's generic access.SCIMClient handles the wire-level
// request / response plumbing; this file composes the client with
// the okta connector's config + secrets so the connector satisfies
// the access.SCIMProvisioner optional interface.
//
// Composition (rather than embedding) keeps the SCIM dispatch
// stateless on the connector: every call adapts (cfg, secrets) into
// the generic SCIMClient's config map and delegates.
package okta

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// scimClient is the package-level SCIMClient instance used by the
// SCIM* methods on OktaAccessConnector. Initialised on first use so
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

// scimConfig adapts the okta connector's (configRaw, secretsRaw)
// pair into the SCIMClient's config / secrets maps. The Okta SCIM
// endpoint base URL is derived from okta_domain; the auth header
// reuses the SSWS API token (Okta's SCIM endpoint accepts the
// standard API token, the same one the rest of the connector uses).
//
// Returns the (config, secrets) maps the SCIMClient expects.
// Callers MUST validate the connector config first (Validate); this
// function returns ErrSCIMConfigInvalid-equivalent errors verbatim
// so the SCIMClient sentinel taxonomy stays intact.
func (c *OktaAccessConnector) scimConfig(configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, nil, err
	}
	domain := cfg.normalisedDomain()
	if domain == "" {
		return nil, nil, fmt.Errorf("okta: scim: okta_domain is required")
	}
	scimBaseURL := "https://" + domain + "/api/scim/v2"
	if c.urlOverride != "" {
		// Tests point the connector at an httptest.Server; mirror
		// the same override into the SCIM dispatch so the SCIM
		// requests land at the test server too.
		scimBaseURL = strings.TrimRight(c.urlOverride, "/") + "/api/scim/v2"
	}
	scimCfg := map[string]interface{}{
		"scim_base_url": scimBaseURL,
	}
	scimSecrets := map[string]interface{}{
		// Okta's SCIM endpoint accepts the SSWS API token via the
		// Authorization header. Mirror the rest of the connector's
		// "with or without SSWS prefix" tolerance.
		"scim_auth_header": "SSWS " + strings.TrimPrefix(secrets.APIToken, "SSWS "),
	}
	return scimCfg, scimSecrets, nil
}

// PushSCIMUser satisfies access.SCIMProvisioner. Delegates to the
// shared SCIMClient against the Okta SCIM v2.0 endpoint.
func (c *OktaAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMUser(ctx, scimCfg, scimSecrets, user)
}

// PushSCIMGroup satisfies access.SCIMProvisioner. Delegates to the
// shared SCIMClient against the Okta SCIM v2.0 endpoint.
func (c *OktaAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMGroup(ctx, scimCfg, scimSecrets, group)
}

// DeleteSCIMResource satisfies access.SCIMProvisioner. Delegates to
// the shared SCIMClient. resourceType MUST be "Users" or "Groups"
// per RFC 7644 §3.4.1.
func (c *OktaAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, resourceType, externalID)
}
