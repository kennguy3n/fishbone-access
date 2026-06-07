// Package google_workspace implements the access.AccessConnector contract for
// Google Workspace via the Admin SDK Directory API.
//
// Capabilities:
//
//   - Validate (pure-local), Connect, VerifyPermissions
//   - CountIdentities, SyncIdentities (Admin SDK Directory users.list)
//   - GroupSyncer (CountGroups, SyncGroups, SyncGroupMembers)
//   - GetSSOMetadata (Google OIDC metadata)
//   - GetCredentialsMetadata (returns service-account key id + client email)
//   - ProvisionAccess / RevokeAccess / ListEntitlements: real group
//     membership routing (and license:* prefix for the Licensing API).
package google_workspace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2/google"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// ErrNotImplemented is retained for any future capability that is not yet
// implemented; ProvisionAccess / RevokeAccess / ListEntitlements no longer
// return it now that the advanced capabilities are implemented.
var ErrNotImplemented = fmt.Errorf("google_workspace: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

const (
	directoryBaseURL = "https://admin.googleapis.com/admin/directory/v1"
	licensingBaseURL = "https://www.googleapis.com/apps/licensing/v1/product"
	googleOIDCURL    = "https://accounts.google.com/.well-known/openid-configuration"
)

// adminSDKScopes are the Admin SDK Directory scopes required for read-only
// identity / group sync. Used by directoryClient (Connect probe, identity
// sync, group sync, ListEntitlements).
var adminSDKScopes = []string{
	"https://www.googleapis.com/auth/admin.directory.user.readonly",
	"https://www.googleapis.com/auth/admin.directory.group.readonly",
	"https://www.googleapis.com/auth/admin.directory.group.member.readonly",
}

// adminSDKWriteScopes are required for ProvisionAccess / RevokeAccess: the
// non-readonly group.member scope authorizes POST / DELETE on
// /groups/{id}/members, and apps.licensing authorizes the Licensing API
// product/sku assign + unassign endpoints. The read-only directory.user
// scope is retained so the same client can still drive ListEntitlements
// pagination if a caller chooses to share it.
var adminSDKWriteScopes = []string{
	"https://www.googleapis.com/auth/admin.directory.user.readonly",
	"https://www.googleapis.com/auth/admin.directory.group.readonly",
	"https://www.googleapis.com/auth/admin.directory.group.member",
	"https://www.googleapis.com/auth/apps.licensing",
}

// scimProvisioningScopes are required by the SCIM provisioning path
// (PushSCIMUser / PushSCIMGroup / DeleteSCIMResource), which performs
// POST / PUT / DELETE against the Admin SDK Directory /Users, /Groups,
// and /Groups/{id}/members surfaces. Unlike adminSDKWriteScopes (which
// only needs to mutate group membership for ProvisionAccess), SCIM
// creates and deletes the user and group resources themselves, so it
// needs the non-readonly directory.user and directory.group scopes.
// Minting the SCIM token with the read-only adminSDKScopes would make
// every write return 403 Forbidden.
var scimProvisioningScopes = []string{
	"https://www.googleapis.com/auth/admin.directory.user",
	"https://www.googleapis.com/auth/admin.directory.group",
	"https://www.googleapis.com/auth/admin.directory.group.member",
}

// adminReportsScopes are required by the Admin SDK *Reports* API
// (admin.googleapis.com/admin/reports/v1) that backs FetchAccessAuditLogs
// and SyncIdentitiesDelta. The Reports API is a distinct surface from the
// Directory API and is NOT authorized by any admin.directory.* scope:
// minting the token with adminSDKScopes makes every reports call return
// 403 Forbidden in production.
var adminReportsScopes = []string{
	"https://www.googleapis.com/auth/admin.reports.audit.readonly",
}

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// GoogleWorkspaceAccessConnector implements access.AccessConnector and
// access.GroupSyncer for Google Workspace.
type GoogleWorkspaceAccessConnector struct {
	httpClientFor func(ctx context.Context, cfg Config, secrets Secrets) (httpDoer, error)
	// writeHTTPClientFor mirrors httpClientFor for tests that want to
	// assert that ProvisionAccess / RevokeAccess use the write-capable
	// client. When nil, write paths fall back to httpClientFor (so
	// existing tests continue to work without modification).
	writeHTTPClientFor func(ctx context.Context, cfg Config, secrets Secrets) (httpDoer, error)
	// scimBearerTokenFor lets the SCIM composition skip the JWT
	// dance in tests and return a static token. Production paths
	// leave this nil and acquire a token via the service-account
	// JWT flow.
	scimBearerTokenFor func(ctx context.Context, cfg Config, secrets Secrets) (string, error)
	// scimURLOverride redirects the SCIM endpoint base URL to a
	// local httptest.Server for tests.
	scimURLOverride string
}

// New constructs a fresh connector instance.
func New() *GoogleWorkspaceAccessConnector {
	return &GoogleWorkspaceAccessConnector{}
}

// ---------- Validate / Connect / VerifyPermissions ----------

// Validate is pure-local. It JSON-parses the service-account key to confirm
// shape but never makes a network call.
func (c *GoogleWorkspaceAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

// Connect verifies credentials by calling /admin/directory/v1/users with
// maxResults=1. The 200 response confirms domain-wide delegation and scopes
// are provisioned correctly.
func (c *GoogleWorkspaceAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client, err := c.directoryClient(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/users?domain=%s&maxResults=1", directoryBaseURL, url.QueryEscape(cfg.Domain)), nil)
	if err != nil {
		return err
	}
	if _, err := doJSON(client, req); err != nil {
		return fmt.Errorf("google_workspace: connect probe: %w", err)
	}
	return nil
}

// VerifyPermissions probes the provider per the AccessConnector contract
// (types.go: "probes the provider per requested capability"). It runs the
// same credential/scope check as Connect and reports any requested
// capability the connector cannot service. A probe failure means the
// service-account key, domain-wide delegation, or directory scopes are not
// provisioned, so every requested capability is unauthorized — matching the
// behaviour of every other API-backed connector in this package, which all
// delegate to Connect. Capability names with no scope mapping can never be
// satisfied and are always reported as missing.
func (c *GoogleWorkspaceAccessConnector) VerifyPermissions(
	ctx context.Context,
	configRaw map[string]interface{},
	secretsRaw map[string]interface{},
	capabilities []string,
) ([]string, error) {
	known := map[string]bool{
		"sync_identity": true,
	}
	var missing []string
	for _, cap := range capabilities {
		if !known[cap] {
			missing = append(missing, fmt.Sprintf("%s (no scope mapping)", cap))
		}
	}
	// Probe the provider; an error means the known capabilities are
	// unauthorized (bad key, missing delegation, or insufficient scopes).
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		for _, cap := range capabilities {
			if known[cap] {
				missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
			}
		}
	}
	return missing, nil
}

// ---------- Identity sync ----------

// CountIdentities fetches a single page with maxResults=1 and reads
// totalResults if Google returns it. Otherwise returns -1 to signal unknown.
func (c *GoogleWorkspaceAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	client, err := c.directoryClient(ctx, cfg, secrets)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/users?domain=%s&maxResults=1", directoryBaseURL, url.QueryEscape(cfg.Domain)), nil)
	if err != nil {
		return 0, err
	}
	body, err := doJSON(client, req)
	if err != nil {
		return 0, err
	}
	var page directoryUsersPage
	if err := json.Unmarshal(body, &page); err != nil {
		return 0, fmt.Errorf("google_workspace: decode count: %w", err)
	}
	// The Admin SDK does not expose a stable totalResults — return -1 so
	// callers know the number is unknown rather than zero.
	return -1, nil
}

// SyncIdentities pages through users.list with pageToken pagination.
func (c *GoogleWorkspaceAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client, err := c.directoryClient(ctx, cfg, secrets)
	if err != nil {
		return err
	}

	pageToken := checkpoint
	for {
		next, err := url.Parse(directoryBaseURL + "/users")
		if err != nil {
			return err
		}
		q := next.Query()
		q.Set("domain", cfg.Domain)
		q.Set("maxResults", "500")
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		next.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next.String(), nil)
		if err != nil {
			return err
		}
		body, err := doJSON(client, req)
		if err != nil {
			return err
		}
		var page directoryUsersPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("google_workspace: decode users page: %w", err)
		}
		batch := mapDirectoryUsers(page.Users)
		if err := handler(batch, page.NextPageToken); err != nil {
			return err
		}
		if page.NextPageToken == "" {
			return nil
		}
		pageToken = page.NextPageToken
	}
}

// ---------- Group sync ----------

func (c *GoogleWorkspaceAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	client, err := c.directoryClient(ctx, cfg, secrets)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/groups?domain=%s&maxResults=1", directoryBaseURL, url.QueryEscape(cfg.Domain)), nil)
	if err != nil {
		return 0, err
	}
	if _, err := doJSON(client, req); err != nil {
		return 0, err
	}
	return -1, nil
}

func (c *GoogleWorkspaceAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client, err := c.directoryClient(ctx, cfg, secrets)
	if err != nil {
		return err
	}

	pageToken := checkpoint
	for {
		next, err := url.Parse(directoryBaseURL + "/groups")
		if err != nil {
			return err
		}
		q := next.Query()
		q.Set("domain", cfg.Domain)
		q.Set("maxResults", "200")
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		next.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next.String(), nil)
		if err != nil {
			return err
		}
		body, err := doJSON(client, req)
		if err != nil {
			return err
		}
		var page directoryGroupsPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("google_workspace: decode groups page: %w", err)
		}
		batch := mapDirectoryGroups(page.Groups)
		if err := handler(batch, page.NextPageToken); err != nil {
			return err
		}
		if page.NextPageToken == "" {
			return nil
		}
		pageToken = page.NextPageToken
	}
}

func (c *GoogleWorkspaceAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if groupExternalID == "" {
		return errors.New("google_workspace: group external id is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client, err := c.directoryClient(ctx, cfg, secrets)
	if err != nil {
		return err
	}

	pageToken := checkpoint
	for {
		next, err := url.Parse(fmt.Sprintf("%s/groups/%s/members", directoryBaseURL, url.PathEscape(groupExternalID)))
		if err != nil {
			return err
		}
		q := next.Query()
		q.Set("maxResults", "200")
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		next.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next.String(), nil)
		if err != nil {
			return err
		}
		body, err := doJSON(client, req)
		if err != nil {
			return err
		}
		var page directoryMembersPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("google_workspace: decode members page: %w", err)
		}
		ids := make([]string, 0, len(page.Members))
		for _, m := range page.Members {
			if m.ID != "" {
				ids = append(ids, m.ID)
			}
		}
		if err := handler(ids, page.NextPageToken); err != nil {
			return err
		}
		if page.NextPageToken == "" {
			return nil
		}
		pageToken = page.NextPageToken
	}
}

// ---------- advanced capabilities ----------

// ProvisionAccess routes by grant.Role prefix:
//   - "license:<productId>/<skuId>" → Licensing API: assign the SKU to the user.
//   - default                       → Admin SDK Directory: add the user as a
//     member of the group identified by grant.ResourceExternalID. The role
//     payload (`MEMBER` / `MANAGER` / `OWNER`) defaults to `MEMBER` and may be
//     overridden by stripping the `group:` prefix from grant.Role.
//
// 409 Conflict on group-add and "already exists" on license-assign are treated
// as idempotent success per docs/architecture.md §2.
func (c *GoogleWorkspaceAccessConnector) ProvisionAccess(
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
	client, err := c.directoryWriteClient(ctx, cfg, secrets)
	if err != nil {
		return err
	}

	if productID, skuID, ok := parseLicenseRole(grant.Role); ok {
		return provisionLicense(ctx, client, productID, skuID, grant.UserExternalID)
	}

	role := strings.TrimPrefix(grant.Role, "group:")
	if role == "" {
		role = "MEMBER"
	}
	body, err := json.Marshal(directoryMemberAdd{Email: grant.UserExternalID, Role: role})
	if err != nil {
		return fmt.Errorf("google_workspace: marshal member: %w", err)
	}
	urlStr := fmt.Sprintf("%s/groups/%s/members", directoryBaseURL, url.PathEscape(grant.ResourceExternalID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("google_workspace: provision request: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	// 200/201 = added, 409 = already a member (idempotent). Classify the
	// rest with the shared helpers so a 5xx/429 (which the Admin SDK throws
	// aggressively when rate-limiting directory mutations) surfaces as a
	// transient error the worker will retry.
	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated:
		return nil
	case access.IsIdempotentProvisionStatus(resp.StatusCode, rb):
		return nil
	case access.IsTransientStatus(resp.StatusCode):
		return fmt.Errorf("google_workspace: provision transient status %d: %s", resp.StatusCode, string(rb))
	default:
		return fmt.Errorf("google_workspace: provision status %d: %s", resp.StatusCode, string(rb))
	}
}

// RevokeAccess removes the user from a group (or unassigns a license). 404 is
// idempotent success.
func (c *GoogleWorkspaceAccessConnector) RevokeAccess(
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
	client, err := c.directoryWriteClient(ctx, cfg, secrets)
	if err != nil {
		return err
	}

	var urlStr string
	if productID, skuID, ok := parseLicenseRole(grant.Role); ok {
		urlStr = fmt.Sprintf("%s/%s/sku/%s/user/%s",
			licensingBaseURL,
			url.PathEscape(productID),
			url.PathEscape(skuID),
			url.PathEscape(grant.UserExternalID),
		)
	} else {
		urlStr = fmt.Sprintf("%s/groups/%s/members/%s",
			directoryBaseURL,
			url.PathEscape(grant.ResourceExternalID),
			url.PathEscape(grant.UserExternalID),
		)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, urlStr, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("google_workspace: revoke request: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	// 200/204 = removed, 404 = already absent (idempotent). Classify the
	// rest with the shared helpers so a 5xx/429 surfaces as a transient
	// error the worker will retry.
	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent:
		return nil
	case access.IsIdempotentRevokeStatus(resp.StatusCode, rb):
		return nil
	case access.IsTransientStatus(resp.StatusCode):
		return fmt.Errorf("google_workspace: revoke transient status %d: %s", resp.StatusCode, string(rb))
	default:
		return fmt.Errorf("google_workspace: revoke status %d: %s", resp.StatusCode, string(rb))
	}
}

// ListEntitlements pages through the user's group memberships. Each group is
// surfaced as Entitlement{ResourceExternalID: groupID, Role: "member",
// Source: "direct"}.
func (c *GoogleWorkspaceAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("google_workspace: user external id is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	client, err := c.directoryClient(ctx, cfg, secrets)
	if err != nil {
		return nil, err
	}

	var out []access.Entitlement
	pageToken := ""
	for {
		next, err := url.Parse(directoryBaseURL + "/groups")
		if err != nil {
			return nil, err
		}
		q := next.Query()
		q.Set("userKey", userExternalID)
		q.Set("maxResults", "200")
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		next.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next.String(), nil)
		if err != nil {
			return nil, err
		}
		body, err := doJSON(client, req)
		if err != nil {
			return nil, err
		}
		var page directoryGroupsPage
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("google_workspace: decode groups page: %w", err)
		}
		for _, g := range page.Groups {
			out = append(out, access.Entitlement{
				ResourceExternalID: g.ID,
				Role:               "member",
				Source:             "direct",
			})
		}
		if page.NextPageToken == "" {
			return out, nil
		}
		pageToken = page.NextPageToken
	}
}

func validateGrantPair(grant access.AccessGrant) error {
	if grant.UserExternalID == "" {
		return errors.New("google_workspace: grant.UserExternalID is required")
	}
	if grant.ResourceExternalID == "" {
		return errors.New("google_workspace: grant.ResourceExternalID is required")
	}
	return nil
}

// parseLicenseRole returns (productID, skuID, true) for grant roles of the
// form "license:<productId>/<skuId>".
func parseLicenseRole(role string) (string, string, bool) {
	if !strings.HasPrefix(role, "license:") {
		return "", "", false
	}
	spec := strings.TrimPrefix(role, "license:")
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func provisionLicense(ctx context.Context, client httpDoer, productID, skuID, userKey string) error {
	urlStr := fmt.Sprintf("%s/%s/sku/%s/user", licensingBaseURL, url.PathEscape(productID), url.PathEscape(skuID))
	body, err := json.Marshal(map[string]string{"userId": userKey})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("google_workspace: license assign request: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	// 200/201 = assigned, 409 = already assigned (idempotent). Classify the
	// rest with the shared helpers so a 5xx/429 surfaces as a transient
	// error the worker will retry.
	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated:
		return nil
	case access.IsIdempotentProvisionStatus(resp.StatusCode, rb):
		return nil
	case access.IsTransientStatus(resp.StatusCode):
		return fmt.Errorf("google_workspace: license assign transient status %d: %s", resp.StatusCode, string(rb))
	default:
		return fmt.Errorf("google_workspace: license assign status %d: %s", resp.StatusCode, string(rb))
	}
}

// ---------- Metadata ----------

func (c *GoogleWorkspaceAccessConnector) GetSSOMetadata(_ context.Context, _, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return &access.SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: googleOIDCURL,
		EntityID:    "https://accounts.google.com",
		SSOLoginURL: "https://accounts.google.com/o/oauth2/v2/auth",
	}, nil
}

// GetCredentialsMetadata returns the service-account key fingerprint and
// client email. Service account keys do not expire by default but operators
// may still rotate them; we surface the key id so the renewal cron can
// detect a swap.
func (c *GoogleWorkspaceAccessConnector) GetCredentialsMetadata(_ context.Context, _, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	var key serviceAccountKey
	// Already validated to parse; we ignore the second-decode error path.
	_ = json.Unmarshal([]byte(s.ServiceAccountKey), &key)
	return map[string]interface{}{
		"provider":       ProviderName,
		"private_key_id": key.PrivateKeyID,
		"client_email":   key.ClientEmail,
		"project_id":     key.ProjectID,
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

// directoryClient builds a JWT-config OAuth2 client that impersonates
// AdminEmail via domain-wide delegation. Used for read-only paths
// (Connect probe, identity sync, group sync, ListEntitlements). Tests
// inject a stub via httpClientFor so they never reach Google.
func (c *GoogleWorkspaceAccessConnector) directoryClient(ctx context.Context, cfg Config, secrets Secrets) (httpDoer, error) {
	if c.httpClientFor != nil {
		return c.httpClientFor(ctx, cfg, secrets)
	}
	return c.buildDirectoryClient(ctx, cfg, secrets, adminSDKScopes)
}

// directoryWriteClient is the write-capable counterpart used by
// ProvisionAccess and RevokeAccess (group member POST/DELETE and the
// Licensing API). It mints a token under adminSDKWriteScopes so the
// production OAuth2 path is authorized to mutate state. Tests can
// inject writeHTTPClientFor to observe write traffic separately, or
// rely on httpClientFor as the shared fallback.
func (c *GoogleWorkspaceAccessConnector) directoryWriteClient(ctx context.Context, cfg Config, secrets Secrets) (httpDoer, error) {
	if c.writeHTTPClientFor != nil {
		return c.writeHTTPClientFor(ctx, cfg, secrets)
	}
	if c.httpClientFor != nil {
		return c.httpClientFor(ctx, cfg, secrets)
	}
	return c.buildDirectoryClient(ctx, cfg, secrets, adminSDKWriteScopes)
}

// reportsClient builds the client used by the Admin SDK Reports API
// paths (FetchAccessAuditLogs, SyncIdentitiesDelta). It mints a token
// under adminReportsScopes — the Directory scopes used by
// directoryClient do not authorize the Reports API, so sharing that
// client would 403 in production. Tests inject httpClientFor, which
// bypasses the JWT flow entirely.
func (c *GoogleWorkspaceAccessConnector) reportsClient(ctx context.Context, cfg Config, secrets Secrets) (httpDoer, error) {
	if c.httpClientFor != nil {
		return c.httpClientFor(ctx, cfg, secrets)
	}
	return c.buildDirectoryClient(ctx, cfg, secrets, adminReportsScopes)
}

func (c *GoogleWorkspaceAccessConnector) buildDirectoryClient(ctx context.Context, cfg Config, secrets Secrets, scopes []string) (httpDoer, error) {
	jwtConfig, err := google.JWTConfigFromJSON([]byte(secrets.ServiceAccountKey), scopes...)
	if err != nil {
		return nil, fmt.Errorf("google_workspace: parse service account key: %w", err)
	}
	jwtConfig.Subject = cfg.AdminEmail
	return jwtConfig.Client(ctx), nil
}

func doJSON(client httpDoer, req *http.Request) ([]byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google_workspace: request %s: %w", req.URL.Path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("google_workspace: %s status %d: %s", req.URL.Path, resp.StatusCode, string(body))
	}
	// Cap the success-path read so a pathologically large response (e.g. a
	// domain with hundreds of thousands of users) cannot drive unbounded
	// memory allocation. 50 MiB comfortably exceeds a maxResults=500 page
	// of Directory API JSON while still bounding worst-case usage.
	return io.ReadAll(io.LimitReader(resp.Body, 50<<20))
}

func mapDirectoryUsers(users []directoryUser) []*access.Identity {
	out := make([]*access.Identity, 0, len(users))
	for _, u := range users {
		out = append(out, &access.Identity{
			ExternalID:  u.ID,
			Type:        access.IdentityTypeUser,
			DisplayName: u.Name.FullName,
			Email:       u.PrimaryEmail,
			Status:      statusFromSuspended(u.Suspended),
		})
	}
	return out
}

func mapDirectoryGroups(groups []directoryGroup) []*access.Identity {
	out := make([]*access.Identity, 0, len(groups))
	for _, g := range groups {
		out = append(out, &access.Identity{
			ExternalID:  g.ID,
			Type:        access.IdentityTypeGroup,
			DisplayName: g.Name,
			Email:       g.Email,
			Status:      "active",
		})
	}
	return out
}

func statusFromSuspended(suspended bool) string {
	if suspended {
		return "suspended"
	}
	return "active"
}

// ---------- Directory DTOs ----------

type directoryUsersPage struct {
	Users         []directoryUser `json:"users"`
	NextPageToken string          `json:"nextPageToken"`
}

type directoryUser struct {
	ID           string `json:"id"`
	PrimaryEmail string `json:"primaryEmail"`
	Suspended    bool   `json:"suspended"`
	Name         struct {
		FullName string `json:"fullName"`
	} `json:"name"`
}

type directoryGroupsPage struct {
	Groups        []directoryGroup `json:"groups"`
	NextPageToken string           `json:"nextPageToken"`
}

type directoryGroup struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type directoryMembersPage struct {
	Members       []directoryMember `json:"members"`
	NextPageToken string            `json:"nextPageToken"`
}

type directoryMember struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type directoryMemberAdd struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// ---------- compile-time interface assertions ----------

var (
	_ access.AccessConnector = (*GoogleWorkspaceAccessConnector)(nil)
	_ access.GroupSyncer     = (*GoogleWorkspaceAccessConnector)(nil)
)
