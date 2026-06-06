// Package knowbe4 — SCIM v2.0 outbound provisioning composition.
//
// KnowBe4 exposes a SCIM 2.0 endpoint at
// https://{region}.api.knowbe4.com/scim/v2/. The endpoint is gated
// to KnowBe4 accounts with SCIM provisioning enabled and uses a
// dedicated SCIM bearer token (distinct from the v1 reporting API
// token used for /v1/users sync). We surface that token as the
// `scim_token` secret. The region in scim_base_url mirrors the
// region used for /v1 endpoints so a tenant on us.api.knowbe4.com
// for sync also lands on us.api.knowbe4.com for SCIM.
package knowbe4

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// scimClient holds the process-wide SCIMClient behind an atomic pointer so
// both the lazy initialization and SetSCIMClientForTest are goroutine-safe,
// letting SCIM tests run with t.Parallel() without data races.
var scimClient atomic.Pointer[access.SCIMClient]

func scim() *access.SCIMClient {
	if c := scimClient.Load(); c != nil {
		return c
	}
	c := access.NewSCIMClient()
	if scimClient.CompareAndSwap(nil, c) {
		return c
	}
	return scimClient.Load()
}

// SetSCIMClientForTest swaps the package-level SCIMClient and returns
// the previous one so tests can restore it on cleanup.
func SetSCIMClientForTest(c *access.SCIMClient) *access.SCIMClient {
	prev := scim()
	scimClient.Store(c)
	return prev
}

// knowbe4SCIMBaseURL derives the SCIM base URL from the same region
// the /v1 reporting API uses, so a tenant on us.api.knowbe4.com lands
// on us.api.knowbe4.com/scim/v2.
func knowbe4SCIMBaseURL(cfg Config) string {
	r := strings.TrimSpace(cfg.Region)
	if r == "" || strings.EqualFold(r, "us") {
		return "https://us.api.knowbe4.com/scim/v2"
	}
	return "https://" + strings.ToLower(r) + ".api.knowbe4.com/scim/v2"
}

// scimConfig adapts KnowBe4's per-tenant (configRaw, secretsRaw) pair
// into the `scim_base_url` + `scim_auth_header` pair the shared
// SCIMClient expects. The base URL defaults to the region-derived host
// (https://{region}.api.knowbe4.com/scim/v2) and is overridable from
// configRaw["scim_base_url"] for self-hosted SCIM proxies and tests —
// a URL endpoint is configuration, not a credential, so the override
// is read from configRaw to match the convention used by aws/scim.go,
// datadog/scim.go, zendesk/scim.go, etc. The auth header is always
// `Bearer {scim_token}` (the dedicated SCIM token, distinct from the
// v1 reporting API token).
func (c *KnowBe4AccessConnector) scimConfig(configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	cfg, _, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, nil, err
	}
	token, _ := secretsRaw["scim_token"].(string)
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil, errors.New("knowbe4: scim_token is required for SCIM provisioning")
	}
	base := knowbe4SCIMBaseURL(cfg)
	if override, ok := configRaw["scim_base_url"].(string); ok {
		if v := strings.TrimSpace(override); v != "" {
			base = strings.TrimRight(v, "/")
		}
	}
	if c.urlOverride != "" {
		base = strings.TrimRight(c.urlOverride, "/") + "/scim/v2"
	}
	return map[string]interface{}{
			"scim_base_url": base,
		}, map[string]interface{}{
			"scim_auth_header": "Bearer " + token,
		}, nil
}

func (c *KnowBe4AccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMUser(ctx, scimCfg, scimSecrets, user)
}

func (c *KnowBe4AccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMGroup(ctx, scimCfg, scimSecrets, group)
}

func (c *KnowBe4AccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, resourceType, externalID)
}

var _ access.SCIMProvisioner = (*KnowBe4AccessConnector)(nil)
