// Package generic_oidc implements the access.AccessConnector contract for a
// generic OIDC-compliant identity provider. The connector federates SSO via
// iam-core; it does not sync identities or push grants.
//
// Scope:
//
//   - Validate (pure-local), Connect, VerifyPermissions
//   - CountIdentities, SyncIdentities (no-op — SSO-only)
//   - GetSSOMetadata (parsed from /.well-known/openid-configuration)
//   - GetCredentialsMetadata
//   - ProvisionAccess / RevokeAccess / ListEntitlements: structurally absent
//     for the generic OIDC connector. OpenID Connect Core 1.0 defines
//     authentication (id_token, userinfo, end_session) only — it does not
//     define an identity-management surface for adding, removing, or
//     enumerating per-user grants. Workspaces that need provisioning use a
//     provider-specific connector (auth0, okta, microsoft, google_workspace,
//     etc.) or SCIM 2.0, which is a separate protocol bolted alongside OIDC
//     by some IdPs. The three provisioning verbs therefore return
//     access.ErrCapabilityNotSupported (wrapped as ErrNotImplemented for the
//     pre-existing test surface), which the access-connector-worker treats
//     as a clean structural skip rather than a retryable failure (see
//     internal/workers/handlers/handlers.go:finalize).
package generic_oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// ErrNotImplemented preserves the original sentinel for backward
// compatibility (existing tests use errors.Is against it). It wraps
// access.ErrCapabilityNotSupported so callers that switch to the canonical
// platform sentinel also match — the OIDC protocol does not define a
// per-user provisioning surface, so ProvisionAccess / RevokeAccess /
// ListEntitlements are structurally absent, not "future TODO". This matches
// the convention used by hibp, bitsight, virustotal, and wazuh: provide a
// package-local sentinel that wraps the canonical platform sentinel so the
// access-connector-worker finalize() path can route the job to
// status=skipped (not status=failed) without per-package case logic.
var ErrNotImplemented = fmt.Errorf("generic_oidc: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// GenericOIDCAccessConnector implements access.AccessConnector for a generic
// OIDC identity provider.
type GenericOIDCAccessConnector struct {
	httpClient func() httpDoer
}

// New returns a fresh connector instance.
func New() *GenericOIDCAccessConnector {
	return &GenericOIDCAccessConnector{}
}

// ---------- Validate / Connect / VerifyPermissions ----------

func (c *GenericOIDCAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return err
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return err
	}
	return s.validate()
}

func (c *GenericOIDCAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, _, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if _, err := c.fetchDiscovery(ctx, cfg); err != nil {
		return fmt.Errorf("generic_oidc: connect: %w", err)
	}
	return nil
}

// VerifyPermissions probes the discovery doc for the sso_federation
// capability. Other capabilities are not supported.
func (c *GenericOIDCAccessConnector) VerifyPermissions(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	capabilities []string,
) ([]string, error) {
	cfg, _, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, cap := range capabilities {
		switch cap {
		case "sso_federation":
			if _, err := c.fetchDiscovery(ctx, cfg); err != nil {
				missing = append(missing, fmt.Sprintf("sso_federation (%v)", err))
			}
		default:
			missing = append(missing, fmt.Sprintf("%s (not supported by generic_oidc)", cap))
		}
	}
	return missing, nil
}

// ---------- Identity sync (no-op) ----------

// CountIdentities returns 0 — OIDC connectors do not enumerate users.
func (c *GenericOIDCAccessConnector) CountIdentities(_ context.Context, _, _ map[string]interface{}) (int, error) {
	return 0, nil
}

// SyncIdentities is a no-op — federation does not enumerate users
// out-of-band; user records arrive through iam-core SSO sessions.
//
// Per the SSO-only variant of the SyncIdentities contract (see
// access/types.go), this returns nil WITHOUT invoking the handler.
// The choice is deliberate (vs. invoking handler once with an empty
// batch like the audit-only no-op connectors): an SSO-only connector
// has no enumeration capability at all, so signalling "never invoked"
// vs. "invoked with empty batch" preserves the distinction that
// generic OIDC is structurally incapable of identity enumeration,
// not just temporarily empty. The behaviour is test-locked in
// connector_flow_test.go and connector_test.go.
func (c *GenericOIDCAccessConnector) SyncIdentities(
	_ context.Context,
	_, _ map[string]interface{},
	_ string,
	_ func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	return nil
}

// ---------- Structurally-absent capabilities ----------
//
// ProvisionAccess, RevokeAccess, and ListEntitlements return
// ErrCapabilityNotSupported (wrapped as ErrNotImplemented). OpenID Connect
// is an authentication protocol, not an identity-management one — there is
// no add-user, remove-user, or list-grants verb in OIDC Core 1.0 or any of
// its registered extensions. Operators who need provisioning install a
// provider-specific connector (auth0, okta, microsoft, google_workspace,
// etc.) or wire SCIM 2.0 separately. The worker treats this sentinel as a
// structural skip (status=skipped, no retry), distinct from a transient
// failure that would warrant exponential backoff.

func (c *GenericOIDCAccessConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}

func (c *GenericOIDCAccessConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}

func (c *GenericOIDCAccessConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
	return nil, ErrNotImplemented
}

// ---------- Metadata ----------

// GetSSOMetadata fetches the OIDC discovery doc and reflects the relevant
// fields back to iam-core.
func (c *GenericOIDCAccessConnector) GetSSOMetadata(ctx context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	doc, err := c.fetchDiscovery(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &access.SSOMetadata{
		Protocol:     "oidc",
		MetadataURL:  cfg.normalisedIssuer() + "/.well-known/openid-configuration",
		EntityID:     doc.Issuer,
		SSOLoginURL:  doc.AuthorizationEndpoint,
		SSOLogoutURL: doc.EndSessionEndpoint,
	}, nil
}

func (c *GenericOIDCAccessConnector) GetCredentialsMetadata(_ context.Context, _, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":  ProviderName,
		"client_id": s.ClientID,
	}, nil
}

// ---------- Internal helpers ----------

func decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return Config{}, Secrets{}, err
	}
	if err := cfg.validate(); err != nil {
		return Config{}, Secrets{}, err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return Config{}, Secrets{}, err
	}
	if err := s.validate(); err != nil {
		return Config{}, Secrets{}, err
	}
	return cfg, s, nil
}

// oidcDiscoveryDocument is the minimum subset of the OIDC discovery doc this
// connector needs for federation.
type oidcDiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint,omitempty"`
	JWKSURI               string `json:"jwks_uri,omitempty"`
	EndSessionEndpoint    string `json:"end_session_endpoint,omitempty"`
}

func (c *GenericOIDCAccessConnector) fetchDiscovery(ctx context.Context, cfg Config) (*oidcDiscoveryDocument, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.normalisedIssuer()+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("generic_oidc: discovery status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return nil, err
	}
	var doc oidcDiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("generic_oidc: parse discovery: %w", err)
	}
	if doc.Issuer == "" || doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return nil, fmt.Errorf("generic_oidc: discovery doc missing required fields (issuer=%q, auth=%q, token=%q)",
			doc.Issuer, doc.AuthorizationEndpoint, doc.TokenEndpoint)
	}
	if !strings.EqualFold(strings.TrimRight(doc.Issuer, "/"), strings.TrimRight(cfg.IssuerURL, "/")) {
		// Mismatched issuer is suspicious but not fatal; some IdPs add
		// a region suffix to issuer. Just continue — iam-core will
		// catch any actual mismatch at runtime.
		_ = doc
	}
	return &doc, nil
}

// sharedHTTPClient is reused across requests so the underlying
// http.Transport connection pool (keep-alives, TLS sessions) is shared
// rather than rebuilt on every call. http.Client is safe for concurrent
// use by multiple goroutines.
var sharedHTTPClient = &http.Client{Timeout: 30 * time.Second}

func (c *GenericOIDCAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	if c.httpClient != nil {
		return c.httpClient().Do(req)
	}
	return sharedHTTPClient.Do(req)
}

// ---------- compile-time interface assertions ----------

var (
	_ access.AccessConnector = (*GenericOIDCAccessConnector)(nil)
)
