// Package generic_saml implements the access.AccessConnector contract for a
// generic SAML 2.0 identity provider. The connector federates SSO via
// iam-core; it does not sync identities or push grants — those live in
// provider-specific connectors.
//
// Scope:
//
//   - Validate (pure-local), Connect, VerifyPermissions
//   - CountIdentities, SyncIdentities (no-op — SSO-only)
//   - GetSSOMetadata (parsed from the IdP metadata XML)
//   - GetCredentialsMetadata
//   - ProvisionAccess / RevokeAccess / ListEntitlements: structurally absent
//     for the generic SAML connector. SAML 2.0 is an SSO assertion protocol
//     — it defines authentication (AuthnRequest, Response, LogoutRequest)
//     and optionally attribute release, but it does NOT define an
//     identity-management surface for adding, removing, or enumerating
//     per-user grants. Workspaces that need provisioning use a
//     provider-specific connector (okta, microsoft, google_workspace, etc.)
//     or SCIM 2.0, which is a separate protocol. The three provisioning
//     verbs therefore return access.ErrCapabilityNotSupported (wrapped as
//     ErrNotImplemented for the pre-existing test surface), which the
//     access-connector-worker treats as a clean structural skip rather than
//     a retryable failure (see internal/workers/handlers/handlers.go:finalize).
package generic_saml

import (
	"context"
	"encoding/xml"
	"errors"
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
// platform sentinel also match — SAML 2.0 does not define a per-user
// provisioning surface, so ProvisionAccess / RevokeAccess /
// ListEntitlements are structurally absent, not "future TODO". This matches
// the convention used by hibp, bitsight, virustotal, and wazuh.
var ErrNotImplemented = fmt.Errorf("generic_saml: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// GenericSAMLAccessConnector implements access.AccessConnector for a SAML
// identity provider. SAML federation is read-only by design.
type GenericSAMLAccessConnector struct {
	httpClient func() httpDoer
}

// New returns a fresh connector instance.
func New() *GenericSAMLAccessConnector {
	return &GenericSAMLAccessConnector{}
}

// ---------- Validate / Connect / VerifyPermissions ----------

func (c *GenericSAMLAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *GenericSAMLAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, _, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	_, err = c.fetchMetadata(ctx, cfg)
	if err != nil {
		return fmt.Errorf("generic_saml: connect: %w", err)
	}
	return nil
}

// VerifyPermissions for the generic SAML connector probes the metadata URL
// to confirm the IdP is reachable. Only the "sso_federation" capability is
// supported; everything else is reported missing.
func (c *GenericSAMLAccessConnector) VerifyPermissions(
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
			if _, err := c.fetchMetadata(ctx, cfg); err != nil {
				missing = append(missing, fmt.Sprintf("sso_federation (%v)", err))
			}
		default:
			missing = append(missing, fmt.Sprintf("%s (not supported by generic_saml)", cap))
		}
	}
	return missing, nil
}

// ---------- Identity sync (no-op) ----------

// CountIdentities returns 0 — SAML connectors do not enumerate users.
func (c *GenericSAMLAccessConnector) CountIdentities(_ context.Context, _, _ map[string]interface{}) (int, error) {
	return 0, nil
}

// SyncIdentities is a no-op for SAML — federation does not enumerate users
// out-of-band; user records arrive through iam-core SSO assertions.
//
// Per the SSO-only variant of the SyncIdentities contract (see
// access/types.go), this returns nil WITHOUT invoking the handler.
// The choice is deliberate (vs. invoking handler once with an empty
// batch like the audit-only no-op connectors): SAML 2.0 has no
// enumeration surface at all, so signalling "never invoked" vs.
// "invoked with empty batch" preserves the distinction that generic
// SAML is structurally incapable of identity enumeration, not just
// temporarily empty. The behaviour is test-locked in
// connector_flow_test.go and connector_test.go.
func (c *GenericSAMLAccessConnector) SyncIdentities(
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
// ErrCapabilityNotSupported (wrapped as ErrNotImplemented). SAML 2.0 is an
// SSO assertion protocol with no identity-management surface. Operators who
// need provisioning install a provider-specific connector (okta, microsoft,
// google_workspace, etc.) or wire SCIM 2.0 separately. The worker treats
// this sentinel as a structural skip (status=skipped, no retry).

func (c *GenericSAMLAccessConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}

func (c *GenericSAMLAccessConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}

func (c *GenericSAMLAccessConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
	return nil, ErrNotImplemented
}

// ---------- Metadata ----------

// GetSSOMetadata fetches the IdP metadata XML and extracts the bits iam-core
// needs to broker SAML for this provider.
func (c *GenericSAMLAccessConnector) GetSSOMetadata(ctx context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	parsed, err := c.fetchMetadata(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &access.SSOMetadata{
		Protocol:            "saml",
		MetadataURL:         cfg.MetadataURL,
		EntityID:            firstNonEmpty(parsed.EntityID, cfg.EntityID),
		SSOLoginURL:         parsed.SSOLoginURL,
		SSOLogoutURL:        parsed.SSOLogoutURL,
		SigningCertificates: parsed.SigningCertificates,
	}, nil
}

func (c *GenericSAMLAccessConnector) GetCredentialsMetadata(_ context.Context, _, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":         ProviderName,
		"has_signing_cert": s.hasSigningCert(),
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

// parsedSAMLMetadata is the minimum we extract from the IdP metadata XML.
type parsedSAMLMetadata struct {
	EntityID            string
	SSOLoginURL         string
	SSOLogoutURL        string
	SigningCertificates []string
}

// fetchMetadata GETs cfg.MetadataURL and parses just enough XML to confirm
// this is a SAML metadata document and to extract the SSO endpoints.
func (c *GenericSAMLAccessConnector) fetchMetadata(ctx context.Context, cfg Config) (parsedSAMLMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.MetadataURL, nil)
	if err != nil {
		return parsedSAMLMetadata{}, err
	}
	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml, */*")

	resp, err := c.doRaw(req)
	if err != nil {
		return parsedSAMLMetadata{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return parsedSAMLMetadata{}, fmt.Errorf("generic_saml: metadata status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return parsedSAMLMetadata{}, err
	}
	return parseSAMLMetadata(body)
}

// sharedHTTPClient is reused across requests so the underlying
// http.Transport connection pool (keep-alives, TLS sessions) is shared
// rather than rebuilt on every call. http.Client is safe for concurrent
// use by multiple goroutines.
var sharedHTTPClient = &http.Client{Timeout: 30 * time.Second}

func (c *GenericSAMLAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	if c.httpClient != nil {
		return c.httpClient().Do(req)
	}
	return sharedHTTPClient.Do(req)
}

// samlEntityDescriptor is the minimum SAML metadata shape we care about.
type samlEntityDescriptor struct {
	XMLName          xml.Name              `xml:"EntityDescriptor"`
	EntityID         string                `xml:"entityID,attr"`
	IDPSSODescriptor *samlIDPSSODescriptor `xml:"IDPSSODescriptor"`
}

type samlIDPSSODescriptor struct {
	SingleSignOnServices []samlEndpoint      `xml:"SingleSignOnService"`
	SingleLogoutServices []samlEndpoint      `xml:"SingleLogoutService"`
	KeyDescriptors       []samlKeyDescriptor `xml:"KeyDescriptor"`
}

type samlEndpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type samlKeyDescriptor struct {
	Use     string `xml:"use,attr"`
	KeyInfo struct {
		X509Data struct {
			X509Certificate string `xml:"X509Certificate"`
		} `xml:"X509Data"`
	} `xml:"KeyInfo"`
}

func parseSAMLMetadata(body []byte) (parsedSAMLMetadata, error) {
	var ed samlEntityDescriptor
	if err := xml.Unmarshal(body, &ed); err != nil {
		return parsedSAMLMetadata{}, fmt.Errorf("generic_saml: parse metadata: %w", err)
	}
	if ed.XMLName.Local != "EntityDescriptor" {
		return parsedSAMLMetadata{}, errors.New("generic_saml: metadata root is not <EntityDescriptor>")
	}
	if ed.IDPSSODescriptor == nil {
		return parsedSAMLMetadata{}, errors.New("generic_saml: metadata is missing <IDPSSODescriptor>")
	}
	out := parsedSAMLMetadata{EntityID: ed.EntityID}
	out.SSOLoginURL = pickBinding(ed.IDPSSODescriptor.SingleSignOnServices)
	out.SSOLogoutURL = pickBinding(ed.IDPSSODescriptor.SingleLogoutServices)
	for _, kd := range ed.IDPSSODescriptor.KeyDescriptors {
		if kd.Use != "" && !strings.EqualFold(kd.Use, "signing") {
			continue
		}
		cert := strings.TrimSpace(kd.KeyInfo.X509Data.X509Certificate)
		if cert != "" {
			out.SigningCertificates = append(out.SigningCertificates, cert)
		}
	}
	return out, nil
}

// pickBinding chooses HTTP-Redirect first, falls back to HTTP-POST, then to
// the first available endpoint.
func pickBinding(eps []samlEndpoint) string {
	for _, ep := range eps {
		if strings.HasSuffix(ep.Binding, "HTTP-Redirect") {
			return ep.Location
		}
	}
	for _, ep := range eps {
		if strings.HasSuffix(ep.Binding, "HTTP-POST") {
			return ep.Location
		}
	}
	if len(eps) > 0 {
		return eps[0].Location
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// ---------- compile-time interface assertions ----------

var (
	_ access.AccessConnector = (*GenericSAMLAccessConnector)(nil)
)
