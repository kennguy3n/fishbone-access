// Package azure implements the access.AccessConnector contract for Azure
// RBAC over Microsoft Graph. The connector authenticates against Entra ID
// with the same client-credentials flow as the microsoft connector but is
// scoped to a single subscription's directory users.
package azure

import (
	"bytes"
	"context"
	// gosec G505 false positive: SHA-1 is used here only to
	// derive a deterministic 128-bit identifier for the Azure
	// ARM role-assignment name (so retries land on the same
	// assignment). Not a cryptographic-strength use.
	"crypto/sha1" // #nosec G505
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/oauth2/microsoft"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName      = "azure"
	defaultBaseURL    = "https://graph.microsoft.com/v1.0"
	defaultARMBaseURL = "https://management.azure.com"
	armAPIVersion     = "2022-04-01"

	// azureSyncMaxPages and azureEntitlementsMaxPages bound the
	// @odata.nextLink pagination walks as defense-in-depth, mirroring
	// azureAuditMaxPages and boxCollaborationsMaxPages. Every walk also
	// stops naturally when nextLink is empty and checks ctx.Err() each
	// iteration; the caps only guard against a misbehaving upstream that
	// keeps emitting fresh cursors. azureSyncMaxPages covers all the
	// directory walks — SyncIdentities (connector.go), SyncGroups and
	// SyncGroupMembers (groups.go) — each of which walks 200 objects/page
	// and reports its cursor to the handler every page, so reaching the
	// cap simply defers the rest to the next sync cycle via the persisted
	// checkpoint and no objects are dropped. The entitlements cap is
	// small because role assignments for a single principal never span
	// anywhere near this many pages.
	azureSyncMaxPages         = 10000
	azureEntitlementsMaxPages = 1000
)

// ErrNotImplemented is retained for any future capability that is not yet
// implemented; ProvisionAccess / RevokeAccess / ListEntitlements no longer
// return it now that the advanced capabilities are implemented.
var ErrNotImplemented = fmt.Errorf("azure: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	TenantID       string `json:"tenant_id"`
	SubscriptionID string `json:"subscription_id"`

	// SSOProtocol selects which federation protocol GetSSOMetadata
	// advertises for the Entra ID tenant. Allowed values are
	// "oidc" (default) and "saml". The two endpoints map to:
	//   oidc: https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration
	//   saml: https://login.microsoftonline.com/{tenant}/federationmetadata/2007-06/federationmetadata.xml
	SSOProtocol string `json:"sso_protocol,omitempty"`
}

type Secrets struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type AzureAccessConnector struct {
	httpClient    func(ctx context.Context, cfg Config, secrets Secrets) httpDoer
	urlOverride   string
	tokenOverride func(ctx context.Context, cfg Config, secrets Secrets) (string, error)
}

func New() *AzureAccessConnector { return &AzureAccessConnector{} }
func init()                      { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("azure: config is nil")
	}
	var cfg Config
	if v, ok := raw["tenant_id"].(string); ok {
		cfg.TenantID = v
	}
	if v, ok := raw["subscription_id"].(string); ok {
		cfg.SubscriptionID = v
	}
	if v, ok := raw["sso_protocol"].(string); ok {
		cfg.SSOProtocol = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("azure: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["client_id"].(string); ok {
		s.ClientID = v
	}
	if v, ok := raw["client_secret"].(string); ok {
		s.ClientSecret = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.TenantID) == "" {
		return errors.New("azure: tenant_id is required")
	}
	if strings.TrimSpace(c.SubscriptionID) == "" {
		return errors.New("azure: subscription_id is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.ClientID) == "" {
		return errors.New("azure: client_id is required")
	}
	if strings.TrimSpace(s.ClientSecret) == "" {
		return errors.New("azure: client_secret is required")
	}
	return nil
}

func (c *AzureAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *AzureAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *AzureAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func newClientCredentialsConfig(cfg Config, secrets Secrets) *clientcredentials.Config {
	return &clientcredentials.Config{
		ClientID:     secrets.ClientID,
		ClientSecret: secrets.ClientSecret,
		TokenURL:     microsoft.AzureADEndpoint(cfg.TenantID).TokenURL,
		Scopes:       []string{"https://graph.microsoft.com/.default"},
	}
}

func (c *AzureAccessConnector) graphClient(ctx context.Context, cfg Config, secrets Secrets) httpDoer {
	if c.httpClient != nil {
		return c.httpClient(ctx, cfg, secrets)
	}
	if c.tokenOverride != nil {
		return &bearerTransportClient{ctx: ctx, cfg: cfg, secrets: secrets, token: c.tokenOverride, inner: &http.Client{Timeout: 30 * time.Second}}
	}
	return newClientCredentialsConfig(cfg, secrets).Client(ctx)
}

type bearerTransportClient struct {
	ctx     context.Context
	cfg     Config
	secrets Secrets
	token   func(ctx context.Context, cfg Config, secrets Secrets) (string, error)
	inner   *http.Client
}

func (b *bearerTransportClient) Do(req *http.Request) (*http.Response, error) {
	tok, err := b.token(b.ctx, b.cfg, b.secrets)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return b.inner.Do(req)
}

// doJSON issues a GET/DELETE against the Microsoft Graph API and
// returns the decoded body. path may be either a base-relative path
// (e.g. "/users?...") or an already-absolute URL (e.g. an
// @odata.nextLink pagination cursor); an absolute URL is used verbatim
// while a relative path is resolved against baseURL(). Accepting the
// cursor as-is means SyncIdentities/SyncGroups/SyncGroupMembers can
// hand the raw nextLink straight back without stripping baseURL, so a
// nextLink that ever points at a different host/format (regional
// endpoint, trailing-slash variation) is followed correctly instead of
// being concatenated into a malformed "baseURLhttps://..." URL. ctx is
// the first parameter per Go convention.
func (c *AzureAccessConnector) doJSON(ctx context.Context, client httpDoer, method, path string) ([]byte, error) {
	endpoint := path
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		endpoint = c.baseURL() + path
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("ConsistencyLevel", "eventual")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("azure: %s %s: status %d: %s", method, path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *AzureAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client := c.graphClient(ctx, cfg, secrets)
	if _, err := c.doJSON(ctx, client, http.MethodGet, "/users?$top=1"); err != nil {
		return fmt.Errorf("azure: connect probe: %w", err)
	}
	return nil
}

func (c *AzureAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type azureUsersResponse struct {
	NextLink string      `json:"@odata.nextLink,omitempty"`
	Count    int         `json:"@odata.count,omitempty"`
	Value    []azureUser `json:"value"`
}

type azureUser struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	UserPrincipalName string `json:"userPrincipalName"`
	Mail              string `json:"mail"`
	AccountEnabled    bool   `json:"accountEnabled"`
}

func (c *AzureAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	client := c.graphClient(ctx, cfg, secrets)
	body, err := c.doJSON(ctx, client, http.MethodGet, "/users/$count")
	if err != nil {
		return 0, err
	}
	// /users/$count returns a plain integer.
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(body)), "%d", &n); err != nil {
		return 0, fmt.Errorf("azure: parse count: %w", err)
	}
	return n, nil
}

func (c *AzureAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client := c.graphClient(ctx, cfg, secrets)
	path := "/users?$select=id,displayName,userPrincipalName,mail,accountEnabled&$top=200"
	if checkpoint != "" {
		path = checkpoint
	}
	for page := 0; page < azureSyncMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		body, err := c.doJSON(ctx, client, http.MethodGet, path)
		if err != nil {
			return err
		}
		var resp azureUsersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("azure: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Value))
		for _, u := range resp.Value {
			email := u.Mail
			if email == "" {
				email = u.UserPrincipalName
			}
			status := "active"
			if !u.AccountEnabled {
				status = "disabled"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: u.DisplayName,
				Email:       email,
				Status:      status,
			})
		}
		// Hand Graph's @odata.nextLink back verbatim; doJSON follows
		// absolute URLs directly, so no fragile baseURL stripping is
		// needed and an unexpected host/format cannot be mangled.
		next := resp.NextLink
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		path = next
	}
	// Hit the defensive page cap; the last handler call carried a
	// non-empty checkpoint, so the next sync cycle resumes from there.
	return nil
}

// armURL returns the absolute ARM URL for the given path. In tests the
// urlOverride covers both Graph and ARM via the same httptest server.
func (c *AzureAccessConnector) armURL(path string) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/") + path
	}
	return defaultARMBaseURL + path
}

// armClient mirrors graphClient but uses the management.azure.com scope when
// running outside of tests.
func (c *AzureAccessConnector) armClient(ctx context.Context, cfg Config, secrets Secrets) httpDoer {
	if c.httpClient != nil {
		return c.httpClient(ctx, cfg, secrets)
	}
	if c.tokenOverride != nil {
		return &bearerTransportClient{ctx: ctx, cfg: cfg, secrets: secrets, token: c.tokenOverride, inner: &http.Client{Timeout: 30 * time.Second}}
	}
	cc := newClientCredentialsConfig(cfg, secrets)
	cc.Scopes = []string{"https://management.azure.com/.default"}
	return cc.Client(ctx)
}

// armRoleAssignmentName builds a deterministic GUID-formatted name from the
// (scope, principalID, roleDefinitionID) tuple so that retries land on the
// same role assignment and 409 / 404 can be treated as idempotent.
func armRoleAssignmentName(scope, principalID, roleDefinitionID string) string {
	// Length-prefix each component before joining so the encoding is
	// injective: two different (scope, principalID, roleDefinitionID)
	// tuples can never hash to the same name regardless of the bytes
	// they contain. (Azure scopes/principal/role ids never contain the
	// old "|" separator today, but length-prefixing removes the
	// assumption entirely.)
	var sb strings.Builder
	for _, part := range []string{scope, principalID, roleDefinitionID} {
		fmt.Fprintf(&sb, "%d:%s", len(part), part)
	}
	// gosec G401: deterministic identifier, not a hash for
	// integrity/auth. SHA-1 chosen so the 20-byte output trims
	// cleanly to a 16-byte GUID-shaped name.
	sum := sha1.Sum([]byte(sb.String())) // #nosec G401
	b := sum[:16]
	// Format as a GUID; this is just a deterministic identifier so we do
	// not tag it as a specific UUID variant.
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ProvisionAccess assigns an Azure RBAC role to the user via PUT
// /subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments/{name}.
// The assignment name is derived deterministically so 409 Conflict (the role
// is already assigned) collapses to idempotent success.
func (c *AzureAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if err := validateGrantPair(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	// PathEscape the subscription id before embedding it in the URL
	// path, mirroring ListEntitlements/FetchAccessAuditLogs. Azure
	// subscription ids are UUIDs in practice, but escaping keeps the
	// URL well-formed if one ever carried a path-special character.
	scope := "/subscriptions/" + url.PathEscape(cfg.SubscriptionID)
	name := armRoleAssignmentName(scope, grant.UserExternalID, grant.ResourceExternalID)
	path := fmt.Sprintf("%s/providers/Microsoft.Authorization/roleAssignments/%s?api-version=%s",
		scope, url.PathEscape(name), armAPIVersion)
	payload := map[string]map[string]string{
		"properties": {
			"roleDefinitionId": grant.ResourceExternalID,
			"principalId":      grant.UserExternalID,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := c.armClient(ctx, cfg, secrets)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.armURL(path), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("azure: provision request: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusConflict:
		return nil
	default:
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode == http.StatusBadRequest && bytes.Contains(rb, []byte("RoleAssignmentExists")) {
			return nil
		}
		return fmt.Errorf("azure: provision status %d: %s", resp.StatusCode, string(rb))
	}
}

// RevokeAccess removes the deterministic role assignment via DELETE. 404 is
// idempotent success.
func (c *AzureAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if err := validateGrantPair(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	// PathEscape the subscription id (same as ProvisionAccess) so the
	// deterministic assignment name derives from an identical scope on
	// both sides and the DELETE URL stays well-formed.
	scope := "/subscriptions/" + url.PathEscape(cfg.SubscriptionID)
	name := armRoleAssignmentName(scope, grant.UserExternalID, grant.ResourceExternalID)
	path := fmt.Sprintf("%s/providers/Microsoft.Authorization/roleAssignments/%s?api-version=%s",
		scope, url.PathEscape(name), armAPIVersion)
	client := c.armClient(ctx, cfg, secrets)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.armURL(path), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("azure: revoke request: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		// Covers 204 No Content (the normal ARM delete response).
		return nil
	case resp.StatusCode == http.StatusNotFound:
		// Assignment already gone ⇒ idempotent success.
		return nil
	default:
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("azure: revoke status %d: %s", resp.StatusCode, string(rb))
	}
}

// ListEntitlements returns the user's role assignments scoped to the
// configured subscription. The OData $filter is used server-side; results
// are paged via @odata.nextLink (the Azure ARM convention is the same as
// Graph's).
func (c *AzureAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("azure: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	client := c.armClient(ctx, cfg, secrets)
	// Escape per OData (double single quotes) and URL-encode the literal
	// before embedding into $filter so a principal id containing quotes
	// cannot break out of the filter string. Mirrors the escaping in
	// GetCredentialsMetadata.
	escapedPrincipalID := strings.ReplaceAll(userExternalID, "'", "''")
	path := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=%s&$filter=%s",
		url.PathEscape(cfg.SubscriptionID), armAPIVersion,
		url.QueryEscape("principalId eq '"+escapedPrincipalID+"'"))
	next := c.armURL(path)
	var out []access.Entitlement
	for pageNum := 0; pageNum < azureEntitlementsMaxPages; pageNum++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("azure: list entitlements: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("azure: list entitlements status %d: %s", resp.StatusCode, string(body))
		}
		var pageResp armRoleAssignmentsResponse
		if err := json.Unmarshal(body, &pageResp); err != nil {
			return nil, fmt.Errorf("azure: decode role assignments: %w", err)
		}
		for _, a := range pageResp.Value {
			out = append(out, access.Entitlement{
				ResourceExternalID: a.Properties.RoleDefinitionID,
				// Role names the role itself, not the assignment
				// scope. The role-assignment payload only carries the
				// roleDefinitionId, so use its canonical trailing id
				// segment (the built-in/custom role's GUID) — the most
				// role-descriptive value available without a secondary
				// roleDefinitions lookup, and consistent with the other
				// connectors that surface the role value straight from
				// the listing response.
				Role:   roleDefinitionShortID(a.Properties.RoleDefinitionID),
				Source: "direct",
			})
		}
		if pageResp.NextLink == "" {
			return out, nil
		}
		// NextLink may be absolute; in tests we re-anchor to the
		// urlOverride so the redirected server still receives it.
		// Mirrors FetchAccessAuditLogs in audit.go.
		if c.urlOverride != "" && strings.HasPrefix(pageResp.NextLink, defaultARMBaseURL) {
			next = strings.TrimRight(c.urlOverride, "/") + strings.TrimPrefix(pageResp.NextLink, defaultARMBaseURL)
		} else {
			next = pageResp.NextLink
		}
	}
	// Hit the defensive page cap; return what we have rather than spin.
	return out, nil
}

// roleDefinitionShortID returns the trailing identifier segment of an
// Azure roleDefinitionId (e.g. ".../roleDefinitions/{guid}" -> "{guid}").
// This is the canonical role identifier and is used for Entitlement.Role
// so the field describes the role rather than the assignment scope.
func roleDefinitionShortID(roleDefinitionID string) string {
	id := strings.TrimRight(strings.TrimSpace(roleDefinitionID), "/")
	if i := strings.LastIndex(id, "/"); i >= 0 {
		return id[i+1:]
	}
	return id
}

func validateGrantPair(grant access.AccessGrant) error {
	if grant.UserExternalID == "" {
		return errors.New("azure: grant.UserExternalID is required")
	}
	if grant.ResourceExternalID == "" {
		return errors.New("azure: grant.ResourceExternalID is required")
	}
	return nil
}

type armRoleAssignmentsResponse struct {
	NextLink string              `json:"nextLink,omitempty"`
	Value    []armRoleAssignment `json:"value"`
}

type armRoleAssignment struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		RoleDefinitionID string `json:"roleDefinitionId"`
		PrincipalID      string `json:"principalId"`
		Scope            string `json:"scope"`
	} `json:"properties"`
}

// GetSSOMetadata returns Entra ID federation metadata that the access
// platform feeds into SSOFederationService.ConfigureBroker. The tenant
// ID alone is enough to derive the canonical Microsoft Entra ID
// metadata document for either OIDC (default) or SAML federation;
// operators select the protocol via the optional sso_protocol config
// field.
//
// OIDC metadata: https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration
// SAML metadata: https://login.microsoftonline.com/{tenant}/federationmetadata/2007-06/federationmetadata.xml
func (c *AzureAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	// SSO federation metadata is derived from the tenant id alone, so do
	// not require subscription_id here (cfg.validate would). This lets a
	// caller fetch metadata before the full RBAC config is populated,
	// matching bamboohr's GetSSOMetadata which deliberately skips the
	// secrets it does not need.
	tenant := strings.TrimSpace(cfg.TenantID)
	if tenant == "" {
		return nil, errors.New("azure: tenant_id is required")
	}
	proto := strings.ToLower(strings.TrimSpace(cfg.SSOProtocol))
	if proto == "" {
		proto = "oidc"
	}
	switch proto {
	case "oidc":
		return &access.SSOMetadata{
			Protocol:    "oidc",
			MetadataURL: fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration", url.PathEscape(tenant)),
			EntityID:    fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", url.PathEscape(tenant)),
			SSOLoginURL: fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", url.PathEscape(tenant)),
		}, nil
	case "saml":
		return &access.SSOMetadata{
			Protocol:     "saml",
			MetadataURL:  fmt.Sprintf("https://login.microsoftonline.com/%s/federationmetadata/2007-06/federationmetadata.xml", url.PathEscape(tenant)),
			EntityID:     fmt.Sprintf("https://sts.windows.net/%s/", url.PathEscape(tenant)),
			SSOLoginURL:  fmt.Sprintf("https://login.microsoftonline.com/%s/saml2", url.PathEscape(tenant)),
			SSOLogoutURL: fmt.Sprintf("https://login.microsoftonline.com/%s/saml2/logout", url.PathEscape(tenant)),
		}, nil
	default:
		return nil, fmt.Errorf("azure: unsupported sso_protocol %q (want oidc | saml)", cfg.SSOProtocol)
	}
}

// GetCredentialsMetadata returns the client-secret expiry advertised by
// the application's credentials in app registration. When the override
// path is missing, the response includes only non-sensitive metadata.
func (c *AzureAccessConnector) GetCredentialsMetadata(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{
		"provider":        ProviderName,
		"tenant_id":       cfg.TenantID,
		"subscription_id": cfg.SubscriptionID,
		"auth_type":       "client_credentials",
		"client_id_short": shortToken(secrets.ClientID),
	}
	client := c.graphClient(ctx, cfg, secrets)
	// Escape per OData (double single quotes) and URL-encode the literal
	// before embedding into $filter, so a non-UUID client_id containing
	// quotes or other special characters cannot break out of the filter.
	escapedClientID := strings.ReplaceAll(secrets.ClientID, "'", "''")
	filter := url.QueryEscape("appId eq '" + escapedClientID + "'")
	body, err := c.doJSON(ctx, client, http.MethodGet, "/applications?$filter="+filter+"&$select=passwordCredentials")
	if err != nil {
		return out, nil
	}
	var resp struct {
		Value []struct {
			PasswordCredentials []struct {
				EndDateTime string `json:"endDateTime"`
				DisplayName string `json:"displayName"`
			} `json:"passwordCredentials"`
		} `json:"value"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return out, nil
	}
	if len(resp.Value) > 0 && len(resp.Value[0].PasswordCredentials) > 0 {
		creds := resp.Value[0].PasswordCredentials
		earliest := ""
		// Microsoft Graph always returns endDateTime as a UTC ISO 8601
		// instant with the trailing Z (e.g. 2027-06-15T00:00:00Z), so a
		// lexicographic min over the consistent format yields the
		// earliest expiry without parsing.
		for _, cred := range creds {
			if cred.EndDateTime != "" && (earliest == "" || cred.EndDateTime < earliest) {
				earliest = cred.EndDateTime
			}
		}
		if earliest != "" {
			out["client_secret_expires_at"] = earliest
		}
	}
	return out, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*AzureAccessConnector)(nil)
