// Package google_workspace — SCIM v2.0 outbound provisioning composition.
//
// The Google Admin SDK Directory API doubles as Workspace's SCIM
// surface for outbound provisioning. The access-platform's generic
// access.SCIMClient handles the wire plumbing; this file composes
// the client with the google_workspace connector's config + secrets
// so the connector satisfies the access.SCIMProvisioner optional
// interface.
//
// Auth: Bearer token from a service-account JWT
// (secrets.service_account_key) impersonating config.admin_email.
package google_workspace

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/oauth2/google"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// scimClient is the package-level SCIMClient instance used by the
// SCIM* methods on GoogleWorkspaceAccessConnector.
var (
	scimClientOnce sync.Once
	scimClient     *access.SCIMClient
)

// scim returns the lazily-constructed SCIMClient.
func scim() *access.SCIMClient {
	scimClientOnce.Do(func() {
		scimClient = access.NewSCIMClient()
	})
	return scimClient
}

// SetSCIMClientForTest swaps the package-level SCIMClient. Returns
// the previous client so the test can restore it via t.Cleanup.
func SetSCIMClientForTest(c *access.SCIMClient) *access.SCIMClient {
	prev := scim()
	scimClient = c
	return prev
}

// scimConfig adapts the google_workspace connector's
// (configRaw, secretsRaw) pair into the SCIMClient's config /
// secrets maps.
func (c *GoogleWorkspaceAccessConnector) scimConfig(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, nil, err
	}
	scimBaseURL := directoryBaseURL
	if c.scimURLOverride != "" {
		scimBaseURL = strings.TrimRight(c.scimURLOverride, "/")
	}
	token, err := c.scimBearerToken(ctx, cfg, secrets)
	if err != nil {
		return nil, nil, fmt.Errorf("google_workspace: scim: acquire token: %w", err)
	}
	scimCfg := map[string]interface{}{
		"scim_base_url": scimBaseURL,
	}
	scimSecrets := map[string]interface{}{
		"scim_auth_header": "Bearer " + token,
	}
	return scimCfg, scimSecrets, nil
}

// scimBearerToken resolves a Google access token via the
// service-account JWT flow. Tests inject a static token via
// scimBearerTokenFor.
func (c *GoogleWorkspaceAccessConnector) scimBearerToken(ctx context.Context, cfg Config, secrets Secrets) (string, error) {
	if c.scimBearerTokenFor != nil {
		return c.scimBearerTokenFor(ctx, cfg, secrets)
	}
	jwtConfig, err := google.JWTConfigFromJSON([]byte(secrets.ServiceAccountKey), adminSDKScopes...)
	if err != nil {
		return "", fmt.Errorf("google_workspace: parse service account key: %w", err)
	}
	jwtConfig.Subject = cfg.AdminEmail
	tok, err := jwtConfig.TokenSource(ctx).Token()
	if err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}

// PushSCIMUser satisfies access.SCIMProvisioner.
func (c *GoogleWorkspaceAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
	scimCfg, scimSecrets, err := c.scimConfig(ctx, configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMUser(ctx, scimCfg, scimSecrets, user)
}

// PushSCIMGroup satisfies access.SCIMProvisioner.
func (c *GoogleWorkspaceAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
	scimCfg, scimSecrets, err := c.scimConfig(ctx, configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMGroup(ctx, scimCfg, scimSecrets, group)
}

// DeleteSCIMResource satisfies access.SCIMProvisioner.
func (c *GoogleWorkspaceAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
	scimCfg, scimSecrets, err := c.scimConfig(ctx, configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, resourceType, externalID)
}
