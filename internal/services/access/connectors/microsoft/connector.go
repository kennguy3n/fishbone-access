// Package microsoft implements the access.AccessConnector contract for
// Microsoft Entra ID (formerly Azure AD).
//
// Capabilities (per docs/architecture.md):
//
//   - Validate (pure-local), Connect, VerifyPermissions
//   - CountIdentities, SyncIdentities (user enumeration)
//   - SyncIdentitiesDelta (incremental, 410 Gone → ErrDeltaTokenExpired)
//   - GroupSyncer (CountGroups, SyncGroups, SyncGroupMembers)
//   - GetSSOMetadata (OIDC discovery URL)
//   - GetCredentialsMetadata (best-effort)
//   - ProvisionAccess / RevokeAccess / ListEntitlements: real implementations
//     against Microsoft Graph `appRoleAssignments`.
//
// API reference patterns are copied from the SN360 Microsoft connector
// (uneycom/shieldnet360-backend/internal/services/connectors/microsoft).
package microsoft

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/oauth2/microsoft"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/access/connectors/connutil"
)

// ErrNotImplemented is retained for any future capability that is deliberately
// stubbed; ProvisionAccess / RevokeAccess / ListEntitlements no longer
// return it now that the advanced capabilities are implemented.
var ErrNotImplemented = fmt.Errorf("microsoft: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

const (
	graphBaseURL = "https://graph.microsoft.com/v1.0"
	loginBaseURL = "https://login.microsoftonline.com"
)

// httpDoer abstracts *http.Client so unit tests can inject a stub without
// reaching the network. Defaults to http.DefaultClient when nil.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// M365AccessConnector implements access.AccessConnector,
// access.IdentityDeltaSyncer, and access.GroupSyncer for Microsoft Entra ID.
type M365AccessConnector struct {
	// httpClientFor lets tests override the OAuth2-aware HTTP client.
	// Production paths leave this nil and use the default OAuth2 builder.
	httpClientFor func(ctx context.Context, cfg Config, secrets Secrets) httpDoer
	// scimBearerTokenFor lets the SCIM composition skip the OAuth2
	// dance in tests and return a static token instead. Production
	// paths leave this nil and acquire a token via the
	// client-credentials flow.
	scimBearerTokenFor func(ctx context.Context, cfg Config, secrets Secrets) (string, error)
	// scimURLOverride redirects the SCIM endpoint base URL to a
	// local httptest.Server for tests. Empty in production.
	scimURLOverride string
}

// New returns a fresh connector instance.
func New() *M365AccessConnector {
	return &M365AccessConnector{}
}

// ---------- Validate / Connect / VerifyPermissions ----------

// Validate is pure-local. No network I/O.
func (c *M365AccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

// Connect verifies credentials by acquiring an OAuth2 access token via the
// client-credentials flow.
func (c *M365AccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if _, err := newClientCredentialsConfig(cfg, secrets).Token(ctx); err != nil {
		return fmt.Errorf("microsoft: authenticate: %w", err)
	}
	return nil
}

// VerifyPermissions checks the token's roles claim against the requested
// capabilities. The connector recognises only "sync_identity"; unknown
// capability strings surface in the missing list verbatim so operators see
// exactly what the platform asked for and what was missing.
func (c *M365AccessConnector) VerifyPermissions(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	capabilities []string,
) ([]string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	tok, err := newClientCredentialsConfig(cfg, secrets).Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("microsoft: authenticate: %w", err)
	}
	roles, _ := extractRolesFromJWT(tok.AccessToken)

	required := map[string][]string{
		"sync_identity": {"User.Read.All", "Group.Read.All", "Directory.Read.All"},
	}

	var missing []string
	for _, cap := range capabilities {
		needed, ok := required[cap]
		if !ok {
			missing = append(missing, fmt.Sprintf("%s (no role mapping)", cap))
			continue
		}
		for _, role := range needed {
			if !contains(roles, role) {
				missing = append(missing, fmt.Sprintf("%s (requires %s)", cap, role))
			}
		}
	}
	return missing, nil
}

// ---------- Identity sync ----------

// CountIdentities returns the @odata.count for /users using
// ConsistencyLevel=eventual. Best-effort.
func (c *M365AccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	client := c.graphClient(ctx, cfg, secrets)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, graphBaseURL+"/users?$count=true&$top=1", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("ConsistencyLevel", "eventual")

	body, err := doJSON(client, req)
	if err != nil {
		return 0, err
	}

	var page graphUsersPage
	if err := json.Unmarshal(body, &page); err != nil {
		return 0, fmt.Errorf("microsoft: decode count: %w", err)
	}
	return page.Count, nil
}

// SyncIdentities pages through /users with $select and invokes handler per
// page with the next-page link as the checkpoint.
func (c *M365AccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client := c.graphClient(ctx, cfg, secrets)

	startURL := buildUsersURL()
	if checkpoint != "" {
		startURL = checkpoint
	}

	for next := startURL; next != ""; {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return err
		}
		body, err := doJSON(client, req)
		if err != nil {
			return err
		}
		var page graphUsersPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("microsoft: decode users page: %w", err)
		}

		batch := mapGraphUsersToIdentities(page.Value)
		if err := handler(batch, page.NextLink); err != nil {
			return err
		}
		next = page.NextLink
	}
	return nil
}

// InitialDeltaCursor walks /users/delta with $select=id&$top=999 just
// long enough to capture the trailing @odata.deltaLink. Microsoft
// Graph does not expose a "now" token for /users/delta — the only
// supported way to get a baseline deltaLink is to enumerate at least
// once. We minimise bandwidth by selecting only the id field; the
// page payloads are discarded. This is an O(users / 999) sequence
// of small GETs, performed once per full-sync run, so the next sync
// can enter the delta path without re-enumerating identities.
//
// 410 Gone here is unexpected (no inbound token can be expired) and
// would only fire if Graph is hostile; surface it as a plain error
// rather than ErrDeltaTokenExpired so the orchestrator does not
// loop on the same baseline.
func (c *M365AccessConnector) InitialDeltaCursor(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
) (string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return "", err
	}
	client := c.graphClient(ctx, cfg, secrets)

	next := graphBaseURL + "/users/delta?$select=id&$top=999"
	var deltaLink string
	for next != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return "", err
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("microsoft: initial delta probe: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			return "", fmt.Errorf("microsoft: initial delta probe status %d: %s", resp.StatusCode, string(body))
		}
		// Defense in depth: $select=id&$top=999 returns ~20-50KB of
		// user IDs per page, but a hostile or misconfigured proxy
		// could in theory stream an unbounded body. Cap to 8 MiB —
		// well above the natural per-page ceiling, low enough to
		// keep memory bounded if the upstream goes pathological.
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		_ = resp.Body.Close()
		if err != nil {
			return "", err
		}
		var page graphDeltaUsersPage
		if err := json.Unmarshal(body, &page); err != nil {
			return "", fmt.Errorf("microsoft: decode initial delta probe page: %w", err)
		}
		if page.DeltaLink != "" {
			deltaLink = page.DeltaLink
		}
		next = page.NextLink
	}
	return deltaLink, nil
}

// SyncIdentitiesDelta exercises Microsoft Graph's /users/delta endpoint. A
// 410 Gone from the provider is translated into access.ErrDeltaTokenExpired
// per docs/architecture.md §2.
func (c *M365AccessConnector) SyncIdentitiesDelta(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	deltaLink string,
	handler func(batch []*access.Identity, removedExternalIDs []string, nextLink string) error,
) (string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return "", err
	}
	client := c.graphClient(ctx, cfg, secrets)

	startURL := graphBaseURL + "/users/delta"
	if deltaLink != "" {
		startURL = deltaLink
	}

	var finalDeltaLink string
	for next := startURL; next != ""; {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return "", err
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("microsoft: delta request: %w", err)
		}

		if resp.StatusCode == http.StatusGone {
			_ = resp.Body.Close()
			return "", access.ErrDeltaTokenExpired
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			return "", fmt.Errorf("microsoft: delta status %d: %s", resp.StatusCode, string(body))
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return "", err
		}

		var page graphDeltaUsersPage
		if err := json.Unmarshal(body, &page); err != nil {
			return "", fmt.Errorf("microsoft: decode delta page: %w", err)
		}

		batch, removed := mapGraphDeltaUsers(page.Value)
		if err := handler(batch, removed, page.NextLink); err != nil {
			return "", err
		}

		if page.DeltaLink != "" {
			finalDeltaLink = page.DeltaLink
		}
		next = page.NextLink
	}
	return finalDeltaLink, nil
}

// ---------- Group sync ----------

// CountGroups returns @odata.count for /groups.
func (c *M365AccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	client := c.graphClient(ctx, cfg, secrets)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, graphBaseURL+"/groups?$count=true&$top=1", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("ConsistencyLevel", "eventual")

	body, err := doJSON(client, req)
	if err != nil {
		return 0, err
	}
	var page graphGroupsPage
	if err := json.Unmarshal(body, &page); err != nil {
		return 0, fmt.Errorf("microsoft: decode group count: %w", err)
	}
	return page.Count, nil
}

// SyncGroups pages through /groups, mapping each group into an Identity with
// Type=group.
func (c *M365AccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client := c.graphClient(ctx, cfg, secrets)

	startURL := graphBaseURL + "/groups?$select=id,displayName,description,mail&$top=999"
	if checkpoint != "" {
		startURL = checkpoint
	}

	for next := startURL; next != ""; {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return err
		}
		body, err := doJSON(client, req)
		if err != nil {
			return err
		}
		var page graphGroupsPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("microsoft: decode groups page: %w", err)
		}

		batch := mapGraphGroupsToIdentities(page.Value)
		if err := handler(batch, page.NextLink); err != nil {
			return err
		}
		next = page.NextLink
	}
	return nil
}

// SyncGroupMembers pages through /groups/{id}/members and yields the list of
// member external IDs per page.
func (c *M365AccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if groupExternalID == "" {
		return errors.New("microsoft: group external id is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client := c.graphClient(ctx, cfg, secrets)

	startURL := fmt.Sprintf("%s/groups/%s/members?$select=id&$top=999", graphBaseURL, url.PathEscape(groupExternalID))
	if checkpoint != "" {
		startURL = checkpoint
	}

	for next := startURL; next != ""; {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return err
		}
		body, err := doJSON(client, req)
		if err != nil {
			return err
		}
		var page graphMembersPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("microsoft: decode members page: %w", err)
		}
		ids := make([]string, 0, len(page.Value))
		for _, m := range page.Value {
			if m.ID != "" {
				ids = append(ids, m.ID)
			}
		}
		if err := handler(ids, page.NextLink); err != nil {
			return err
		}
		next = page.NextLink
	}
	return nil
}

// ---------- advanced capabilities ----------

// ProvisionAccess pushes a Microsoft Graph `appRoleAssignment` for the grant.
// The connector posts to /v1.0/users/{userExternalID}/appRoleAssignments with
// `principalId`, `resourceId` (the service principal), and `appRoleId` derived
// from the grant. A 409 Conflict response is treated as idempotent success per
// docs/architecture.md §2: the assignment already exists. Non-2xx 4xx surfaces a
// permanent error; 5xx is returned verbatim so the worker retries with backoff.
func (c *M365AccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if err := validateGrantPair(grant); err != nil {
		return err
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client := c.graphClient(ctx, cfg, secrets)

	body, err := json.Marshal(graphAppRoleAssignment{
		PrincipalID: grant.UserExternalID,
		ResourceID:  grant.ResourceExternalID,
		AppRoleID:   grant.Role,
	})
	if err != nil {
		return fmt.Errorf("microsoft: marshal assignment: %w", err)
	}

	urlStr := fmt.Sprintf("%s/users/%s/appRoleAssignments", graphBaseURL, url.PathEscape(grant.UserExternalID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("microsoft: provision request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		return nil
	case http.StatusConflict:
		return nil
	default:
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("microsoft: provision status %d: %s", resp.StatusCode, string(respBody))
	}
}

// RevokeAccess removes an `appRoleAssignment` matching the grant. The connector
// first lists the user's assignments, then issues a DELETE for the one whose
// `resourceId` and `appRoleId` match the grant. A 404 on the DELETE is treated
// as idempotent success.
func (c *M365AccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if err := validateGrantPair(grant); err != nil {
		return err
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client := c.graphClient(ctx, cfg, secrets)

	assignmentID, err := c.findAppRoleAssignmentID(ctx, client, grant)
	if err != nil {
		return err
	}
	if assignmentID == "" {
		return nil
	}

	urlStr := fmt.Sprintf("%s/users/%s/appRoleAssignments/%s",
		graphBaseURL,
		url.PathEscape(grant.UserExternalID),
		url.PathEscape(assignmentID),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, urlStr, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("microsoft: revoke request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusNotFound:
		return nil
	default:
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("microsoft: revoke status %d: %s", resp.StatusCode, string(respBody))
	}
}

// ListEntitlements pages through /v1.0/users/{userExternalID}/appRoleAssignments
// and maps each assignment to an Entitlement{ResourceExternalID, Role,
// Source: "direct"}.
func (c *M365AccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("microsoft: user external id is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	client := c.graphClient(ctx, cfg, secrets)

	next := fmt.Sprintf("%s/users/%s/appRoleAssignments", graphBaseURL, url.PathEscape(userExternalID))
	var out []access.Entitlement
	for next != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		body, err := doJSON(client, req)
		if err != nil {
			return nil, err
		}
		var page graphAppRoleAssignmentsPage
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("microsoft: decode appRoleAssignments page: %w", err)
		}
		for _, a := range page.Value {
			out = append(out, access.Entitlement{
				ResourceExternalID: a.ResourceID,
				Role:               a.AppRoleID,
				Source:             "direct",
			})
		}
		next = page.NextLink
	}
	return out, nil
}

func validateGrantPair(grant access.AccessGrant) error {
	if grant.UserExternalID == "" {
		return errors.New("microsoft: grant.UserExternalID is required")
	}
	if grant.ResourceExternalID == "" {
		return errors.New("microsoft: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *M365AccessConnector) findAppRoleAssignmentID(
	ctx context.Context,
	client httpDoer,
	grant access.AccessGrant,
) (string, error) {
	next := fmt.Sprintf("%s/users/%s/appRoleAssignments", graphBaseURL, url.PathEscape(grant.UserExternalID))
	for next != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return "", err
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("microsoft: list assignments: %w", err)
		}
		if resp.StatusCode == http.StatusNotFound {
			_ = resp.Body.Close()
			return "", nil
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			return "", fmt.Errorf("microsoft: list assignments status %d: %s", resp.StatusCode, string(body))
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return "", err
		}
		var page graphAppRoleAssignmentsPage
		if err := json.Unmarshal(body, &page); err != nil {
			return "", fmt.Errorf("microsoft: decode appRoleAssignments page: %w", err)
		}
		for _, a := range page.Value {
			if a.ResourceID == grant.ResourceExternalID && (grant.Role == "" || a.AppRoleID == grant.Role) {
				return a.ID, nil
			}
		}
		next = page.NextLink
	}
	return "", nil
}

// ---------- Metadata ----------

// GetSSOMetadata returns the OIDC discovery URL for the configured tenant.
func (c *M365AccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &access.SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: fmt.Sprintf("%s/%s/v2.0/.well-known/openid-configuration", loginBaseURL, cfg.TenantID),
		EntityID:    fmt.Sprintf("%s/%s/v2.0", loginBaseURL, cfg.TenantID),
		SSOLoginURL: fmt.Sprintf("%s/%s/oauth2/v2.0/authorize", loginBaseURL, cfg.TenantID),
	}, nil
}

// GetCredentialsMetadata returns minimal metadata. Microsoft Entra does not
// expose client-secret expiry to the application itself; operators must
// surface it via the renewal cron and the credential_expired_time column.
func (c *M365AccessConnector) GetCredentialsMetadata(_ context.Context, _, _ map[string]interface{}) (map[string]interface{}, error) {
	return map[string]interface{}{
		"provider": ProviderName,
		"note":     "client secret expiry is not exposed by the Graph API; populate via renewal cron",
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

func newClientCredentialsConfig(cfg Config, secrets Secrets) *clientcredentials.Config {
	return &clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: secrets.ClientSecret,
		TokenURL:     microsoft.AzureADEndpoint(cfg.TenantID).TokenURL,
		Scopes:       []string{"https://graph.microsoft.com/.default"},
	}
}

func (c *M365AccessConnector) graphClient(ctx context.Context, cfg Config, secrets Secrets) httpDoer {
	if c.httpClientFor != nil {
		return c.httpClientFor(ctx, cfg, secrets)
	}
	return newClientCredentialsConfig(cfg, secrets).Client(ctx)
}

func doJSON(client httpDoer, req *http.Request) ([]byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("microsoft: request %s: %w", req.URL.Path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("microsoft: %s status %d: %s", req.URL.Path, resp.StatusCode, string(body))
	}
	return connutil.ReadBody(resp.Body)
}

// extractRolesFromJWT parses the "roles" claim from an Entra-issued JWT
// without verifying the signature (we already obtained the token via the
// trusted token endpoint, so the bearer is trusted). Returns nil roles on a
// malformed token rather than failing — VerifyPermissions surfaces the
// emptiness as missing capabilities.
func extractRolesFromJWT(tokenString string) ([]string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("microsoft: invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("microsoft: decode JWT payload: %w", err)
	}
	var claims struct {
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("microsoft: unmarshal JWT claims: %w", err)
	}
	return claims.Roles, nil
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func mapGraphUsersToIdentities(users []graphUser) []*access.Identity {
	out := make([]*access.Identity, 0, len(users))
	for _, u := range users {
		out = append(out, &access.Identity{
			ExternalID:  u.ID,
			Type:        access.IdentityTypeUser,
			DisplayName: u.DisplayName,
			Email:       firstNonEmpty(u.Mail, u.UserPrincipalName),
			Status:      statusFromAccountEnabled(u.AccountEnabled),
		})
	}
	return out
}

func mapGraphDeltaUsers(users []graphDeltaUser) ([]*access.Identity, []string) {
	identities := make([]*access.Identity, 0, len(users))
	var removed []string
	for _, u := range users {
		if u.Removed != nil {
			if u.ID != "" {
				removed = append(removed, u.ID)
			}
			continue
		}
		identities = append(identities, &access.Identity{
			ExternalID:  u.ID,
			Type:        access.IdentityTypeUser,
			DisplayName: u.DisplayName,
			Email:       firstNonEmpty(u.Mail, u.UserPrincipalName),
			Status:      statusFromAccountEnabled(u.AccountEnabled),
		})
	}
	return identities, removed
}

func mapGraphGroupsToIdentities(groups []graphGroup) []*access.Identity {
	out := make([]*access.Identity, 0, len(groups))
	for _, g := range groups {
		out = append(out, &access.Identity{
			ExternalID:  g.ID,
			Type:        access.IdentityTypeGroup,
			DisplayName: g.DisplayName,
			Email:       g.Mail,
			Status:      "active",
		})
	}
	return out
}

func statusFromAccountEnabled(enabled bool) string {
	if enabled {
		return "active"
	}
	return "disabled"
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func buildUsersURL() string {
	u, _ := url.Parse(graphBaseURL + "/users")
	q := u.Query()
	q.Set("$select", "id,userPrincipalName,mail,displayName,accountEnabled")
	q.Set("$top", "999")
	u.RawQuery = q.Encode()
	return u.String()
}

// ---------- Graph DTOs ----------

type graphUsersPage struct {
	Count    int         `json:"@odata.count"`
	Value    []graphUser `json:"value"`
	NextLink string      `json:"@odata.nextLink"`
}

type graphUser struct {
	ID                string `json:"id"`
	UserPrincipalName string `json:"userPrincipalName"`
	Mail              string `json:"mail"`
	DisplayName       string `json:"displayName"`
	AccountEnabled    bool   `json:"accountEnabled"`
}

type graphDeltaUsersPage struct {
	Value     []graphDeltaUser `json:"value"`
	NextLink  string           `json:"@odata.nextLink"`
	DeltaLink string           `json:"@odata.deltaLink"`
}

type graphDeltaUser struct {
	ID                string                 `json:"id"`
	UserPrincipalName string                 `json:"userPrincipalName"`
	Mail              string                 `json:"mail"`
	DisplayName       string                 `json:"displayName"`
	AccountEnabled    bool                   `json:"accountEnabled"`
	Removed           map[string]interface{} `json:"@removed,omitempty"`
}

type graphGroupsPage struct {
	Count    int          `json:"@odata.count"`
	Value    []graphGroup `json:"value"`
	NextLink string       `json:"@odata.nextLink"`
}

type graphGroup struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	Mail        string `json:"mail"`
}

type graphMembersPage struct {
	Value    []graphMember `json:"value"`
	NextLink string        `json:"@odata.nextLink"`
}

type graphMember struct {
	ID string `json:"id"`
}

type graphAppRoleAssignment struct {
	ID          string `json:"id,omitempty"`
	PrincipalID string `json:"principalId"`
	ResourceID  string `json:"resourceId"`
	AppRoleID   string `json:"appRoleId"`
}

type graphAppRoleAssignmentsPage struct {
	Value    []graphAppRoleAssignment `json:"value"`
	NextLink string                   `json:"@odata.nextLink"`
}

// ---------- compile-time interface assertions ----------

var (
	_ access.AccessConnector     = (*M365AccessConnector)(nil)
	_ access.IdentityDeltaSyncer = (*M365AccessConnector)(nil)
	_ access.GroupSyncer         = (*M365AccessConnector)(nil)
)
