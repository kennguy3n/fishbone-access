// Package gcp implements the access.AccessConnector contract for Google
// Cloud IAM via the cloudresourcemanager.projects.getIamPolicy endpoint.
//
// Members of the project IAM policy are flattened into a list of
// access.Identity records (user / serviceAccount / group). The connector
// authenticates via a service-account JSON key with domain-wide
// delegation disabled — no user impersonation is needed because IAM
// queries are performed against the service account's own permissions.
package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2/google"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName   = "gcp"
	defaultBaseURL = "https://cloudresourcemanager.googleapis.com"
	// cloudPlatformReadScope grants read-only access to GCP project
	// metadata and IAM policies — sufficient for SyncIdentities,
	// CountIdentities, and ListEntitlements.
	cloudPlatformReadScope = "https://www.googleapis.com/auth/cloud-platform.read-only"
	// cloudPlatformWriteScope is required for IAM mutations
	// (setIamPolicy). ProvisionAccess and RevokeAccess use the
	// write-capable client; the read-only client continues to power
	// non-mutating paths.
	cloudPlatformWriteScope = "https://www.googleapis.com/auth/cloud-platform"
	// cloudIdentityReadScope is the OAuth2 scope required by the
	// Cloud Identity Groups API (cloudidentity.googleapis.com). Cloud
	// Identity is a separate API surface from Cloud Resource Manager
	// and rejects tokens minted with only cloud-platform.read-only
	// (returns 403 PERMISSION_DENIED). GroupSyncer methods request
	// this scope explicitly. See:
	// https://cloud.google.com/identity/docs/reference/rest/v1/groups/list
	cloudIdentityReadScope = "https://www.googleapis.com/auth/cloud-identity.groups.readonly"
)

// ErrNotImplemented is retained for any future capability that is not yet
// implemented; ProvisionAccess / RevokeAccess / ListEntitlements no longer
// return it now that the advanced capabilities are implemented.
var ErrNotImplemented = fmt.Errorf("gcp: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	ProjectID string `json:"project_id"`

	// WorkforcePoolID is the GCP Workforce Identity Federation pool ID
	// (e.g. "shieldnet-pool") used by GetSSOMetadata to advertise the
	// pool's OIDC discovery endpoint to SSOFederationService. When
	// empty the connector returns (nil, nil) from GetSSOMetadata.
	WorkforcePoolID string `json:"workforce_pool_id,omitempty"`
	// WorkforcePoolLocation defaults to "global". Other regions must be
	// declared explicitly per GCP's per-region pool layout.
	WorkforcePoolLocation string `json:"workforce_pool_location,omitempty"`

	// CustomerID is the Cloud Identity customer resource id used by
	// the GroupSyncer methods. Accepts either the raw id (e.g.
	// "C0abcd1234" or "my_customer") or the full resource path
	// ("customers/C0abcd1234"); the connector normalises both forms.
	// Required only when GroupSyncer methods are exercised.
	CustomerID string `json:"customer_id,omitempty"`
}

type Secrets struct {
	ServiceAccountJSON string `json:"service_account_json"`
}

type GCPAccessConnector struct {
	httpClient func(ctx context.Context, cfg Config, secrets Secrets) (httpDoer, error)
	// httpWriteClient mirrors httpClient for tests that want to assert
	// ProvisionAccess / RevokeAccess pick the write-capable client. When
	// nil, write paths fall back to httpClient (so existing tests keep
	// working). In production, both fields are nil and the JWT-config
	// builder runs with the appropriate scope.
	httpWriteClient func(ctx context.Context, cfg Config, secrets Secrets) (httpDoer, error)
	urlOverride     string
	tokenOverride   func(ctx context.Context, cfg Config, secrets Secrets) (string, error)
}

func New() *GCPAccessConnector { return &GCPAccessConnector{} }
func init()                    { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("gcp: config is nil")
	}
	var cfg Config
	if v, ok := raw["project_id"].(string); ok {
		cfg.ProjectID = v
	}
	if v, ok := raw["workforce_pool_id"].(string); ok {
		cfg.WorkforcePoolID = v
	}
	if v, ok := raw["workforce_pool_location"].(string); ok {
		cfg.WorkforcePoolLocation = v
	}
	if v, ok := raw["customer_id"].(string); ok {
		cfg.CustomerID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("gcp: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["service_account_json"].(string); ok {
		s.ServiceAccountJSON = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.ProjectID) == "" {
		return errors.New("gcp: project_id is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.ServiceAccountJSON) == "" {
		return errors.New("gcp: service_account_json is required")
	}
	if !strings.Contains(s.ServiceAccountJSON, "private_key") {
		return errors.New("gcp: service_account_json appears malformed (no private_key)")
	}
	return nil
}

func (c *GCPAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *GCPAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *GCPAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

// cloudResourceClient returns a read-only client used by all
// non-mutating paths (Connect probe, SyncIdentities, CountIdentities,
// ListEntitlements, and the initial getIamPolicy step of
// modifyBinding).
func (c *GCPAccessConnector) cloudResourceClient(ctx context.Context, cfg Config, secrets Secrets) (httpDoer, error) {
	return c.cloudResourceClientWithScope(ctx, cfg, secrets, cloudPlatformReadScope)
}

// cloudResourceWriteClient returns a write-capable client used
// exclusively by ProvisionAccess and RevokeAccess (which call
// setIamPolicy). The write scope subsumes the read scope, so the
// embedded getIamPolicy call still works. Tests may inject
// httpWriteClient to observe write traffic separately from read
// traffic.
func (c *GCPAccessConnector) cloudResourceWriteClient(ctx context.Context, cfg Config, secrets Secrets) (httpDoer, error) {
	if c.httpWriteClient != nil {
		return c.httpWriteClient(ctx, cfg, secrets)
	}
	return c.cloudResourceClientWithScope(ctx, cfg, secrets, cloudPlatformWriteScope)
}

// cloudIdentityClient returns a client minted with the Cloud
// Identity Groups read-only scope. Cloud Identity rejects tokens
// minted with only cloud-platform.read-only, so GroupSyncer
// (CountGroups, SyncGroups, SyncGroupMembers) routes through this
// builder rather than reusing cloudResourceClient. Tests share the
// same httpClient hook, so this is transparent for the unit-test
// path; in production the JWT exchange now requests
// cloud-identity.groups.readonly.
func (c *GCPAccessConnector) cloudIdentityClient(ctx context.Context, cfg Config, secrets Secrets) (httpDoer, error) {
	return c.cloudResourceClientWithScope(ctx, cfg, secrets, cloudIdentityReadScope)
}

// cloudResourceClientWithScope is the underlying builder. Test
// overrides (httpClient / tokenOverride) bypass the JWT exchange
// entirely; the scope argument only matters for the production path
// that minted a real OAuth2 access token.
func (c *GCPAccessConnector) cloudResourceClientWithScope(ctx context.Context, cfg Config, secrets Secrets, scope string) (httpDoer, error) {
	if c.httpClient != nil {
		return c.httpClient(ctx, cfg, secrets)
	}
	if c.tokenOverride != nil {
		return &bearerTransportClient{ctx: ctx, cfg: cfg, secrets: secrets, token: c.tokenOverride, inner: &http.Client{Timeout: 30 * time.Second}}, nil
	}
	jwtConfig, err := google.JWTConfigFromJSON([]byte(secrets.ServiceAccountJSON), scope)
	if err != nil {
		return nil, fmt.Errorf("gcp: parse service account: %w", err)
	}
	return jwtConfig.Client(ctx), nil
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

func (c *GCPAccessConnector) doJSON(client httpDoer, ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gcp: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	resBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("gcp: %s %s: status %d: %s", method, path, resp.StatusCode, string(resBody))
	}
	return resBody, nil
}

func (c *GCPAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client, err := c.cloudResourceClient(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	if _, err := c.doJSON(client, ctx, http.MethodGet, "/v1/projects/"+cfg.ProjectID, nil); err != nil {
		return fmt.Errorf("gcp: connect probe: %w", err)
	}
	return nil
}

func (c *GCPAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type iamPolicyResponse struct {
	Version  int          `json:"version,omitempty"`
	Etag     string       `json:"etag,omitempty"`
	Bindings []iamBinding `json:"bindings"`
}

type iamBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

func (c *GCPAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *GCPAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client, err := c.cloudResourceClient(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	body, err := c.doJSON(client, ctx, http.MethodPost, "/v1/projects/"+cfg.ProjectID+":getIamPolicy", []byte(`{}`))
	if err != nil {
		return err
	}
	var policy iamPolicyResponse
	if err := json.Unmarshal(body, &policy); err != nil {
		return fmt.Errorf("gcp: decode policy: %w", err)
	}
	// Members are scoped under bindings. Dedup across bindings, collapse
	// roles per principal.
	type aggregated struct {
		identity *access.Identity
		roles    []string
	}
	dedup := make(map[string]*aggregated)
	for _, b := range policy.Bindings {
		for _, m := range b.Members {
			rec, ok := dedup[m]
			if !ok {
				rec = &aggregated{identity: principalToIdentity(m)}
				dedup[m] = rec
			}
			rec.roles = append(rec.roles, b.Role)
		}
	}
	identities := make([]*access.Identity, 0, len(dedup))
	for _, rec := range dedup {
		if rec.identity == nil {
			continue
		}
		rec.identity.RawData = map[string]interface{}{"roles": rec.roles}
		identities = append(identities, rec.identity)
	}
	return handler(identities, "")
}

func principalToIdentity(member string) *access.Identity {
	idx := strings.Index(member, ":")
	if idx <= 0 {
		return nil
	}
	prefix := member[:idx]
	value := member[idx+1:]
	switch prefix {
	case "user":
		return &access.Identity{
			ExternalID:  value,
			Type:        access.IdentityTypeUser,
			DisplayName: value,
			Email:       value,
			Status:      "active",
		}
	case "serviceAccount":
		return &access.Identity{
			ExternalID:  value,
			Type:        access.IdentityTypeServiceAccount,
			DisplayName: value,
			Email:       value,
			Status:      "active",
		}
	case "group":
		return &access.Identity{
			ExternalID:  value,
			Type:        access.IdentityTypeGroup,
			DisplayName: value,
			Email:       value,
			Status:      "active",
		}
	case "domain", "allUsers", "allAuthenticatedUsers":
		// Skip wildcards — they aren't real principals.
		return nil
	}
	return nil
}

// ProvisionAccess adds the principal `user:{email}` to the IAM binding for
// the requested role on the configured project. The implementation follows
// the canonical GCP read-modify-write pattern: getIamPolicy -> mutate ->
// setIamPolicy. "already bound" is treated as idempotent success.
func (c *GCPAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	return c.modifyBinding(ctx, configRaw, secretsRaw, grant, true)
}

// RevokeAccess removes the `user:{email}` binding for the requested role.
// "member already absent" is idempotent success.
func (c *GCPAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	return c.modifyBinding(ctx, configRaw, secretsRaw, grant, false)
}

// ListEntitlements returns one Entitlement per role binding the user appears
// in on the configured project's IAM policy.
func (c *GCPAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("gcp: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	client, err := c.cloudResourceClient(ctx, cfg, secrets)
	if err != nil {
		return nil, err
	}
	policy, err := c.fetchPolicy(ctx, client, cfg)
	if err != nil {
		return nil, err
	}
	member := "user:" + userExternalID
	var out []access.Entitlement
	for _, b := range policy.Bindings {
		for _, m := range b.Members {
			if m == member {
				out = append(out, access.Entitlement{
					ResourceExternalID: cfg.ProjectID,
					Role:               b.Role,
					Source:             "direct",
				})
				break
			}
		}
	}
	return out, nil
}

func (c *GCPAccessConnector) modifyBinding(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
	add bool,
) error {
	if err := validateGrantPair(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client, err := c.cloudResourceWriteClient(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	policy, err := c.fetchPolicy(ctx, client, cfg)
	if err != nil {
		return err
	}
	member := "user:" + grant.UserExternalID
	role := grant.ResourceExternalID
	changed := false
	if add {
		changed = addMember(policy, role, member)
	} else {
		changed = removeMember(policy, role, member)
	}
	if !changed {
		// Already in desired state — idempotent success.
		return nil
	}
	wrap := map[string]interface{}{"policy": policy}
	body, err := json.Marshal(wrap)
	if err != nil {
		return err
	}
	if _, err := c.doJSON(client, ctx, http.MethodPost,
		"/v1/projects/"+cfg.ProjectID+":setIamPolicy", body); err != nil {
		return err
	}
	return nil
}

func (c *GCPAccessConnector) fetchPolicy(ctx context.Context, client httpDoer, cfg Config) (*iamPolicyResponse, error) {
	body, err := c.doJSON(client, ctx, http.MethodPost,
		"/v1/projects/"+cfg.ProjectID+":getIamPolicy", []byte(`{}`))
	if err != nil {
		return nil, err
	}
	var policy iamPolicyResponse
	if err := json.Unmarshal(body, &policy); err != nil {
		return nil, fmt.Errorf("gcp: decode policy: %w", err)
	}
	return &policy, nil
}

func addMember(policy *iamPolicyResponse, role, member string) bool {
	for i, b := range policy.Bindings {
		if b.Role != role {
			continue
		}
		for _, m := range b.Members {
			if m == member {
				return false
			}
		}
		policy.Bindings[i].Members = append(policy.Bindings[i].Members, member)
		return true
	}
	policy.Bindings = append(policy.Bindings, iamBinding{Role: role, Members: []string{member}})
	return true
}

func removeMember(policy *iamPolicyResponse, role, member string) bool {
	for i, b := range policy.Bindings {
		if b.Role != role {
			continue
		}
		for j, m := range b.Members {
			if m != member {
				continue
			}
			// Drop members[j] from the binding in place via
			// slices.Delete. This is the canonical idiom for
			// element removal — equivalent to append-splice
			// but keeps gocritic's appendAssign quiet and is
			// easier to reason about.
			policy.Bindings[i].Members = slices.Delete(policy.Bindings[i].Members, j, j+1)
			return true
		}
		return false
	}
	return false
}

func validateGrantPair(grant access.AccessGrant) error {
	if grant.UserExternalID == "" {
		return errors.New("gcp: grant.UserExternalID is required")
	}
	if grant.ResourceExternalID == "" {
		return errors.New("gcp: grant.ResourceExternalID is required")
	}
	return nil
}

// GetSSOMetadata returns OIDC federation metadata for a GCP Workforce
// Identity Federation pool. The operator supplies a workforce_pool_id
// (and optionally workforce_pool_location, default "global"); the
// connector derives the canonical pool issuer and discovery URL that
// SSOFederationService.ConfigureBroker feeds into iam-core.
//
// When workforce_pool_id is empty the method returns (nil, nil) —
// the connector still works for IAM identity sync but SSO federation
// is opt-in.
func (c *GCPAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	pool := strings.TrimSpace(cfg.WorkforcePoolID)
	if pool == "" {
		return nil, nil
	}
	location := strings.TrimSpace(cfg.WorkforcePoolLocation)
	if location == "" {
		location = "global"
	}
	issuer := "https://iam.googleapis.com/locations/" + url.PathEscape(location) +
		"/workforcePools/" + url.PathEscape(pool)
	return &access.SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: issuer + "/.well-known/openid-configuration",
		EntityID:    issuer,
		SSOLoginURL: "https://auth.cloud.google/signin/locations/" + url.PathEscape(location) +
			"/workforcePools/" + url.PathEscape(pool),
	}, nil
}

// GetCredentialsMetadata extracts the service account email + key id from
// the JSON credentials. We never echo the private key.
func (c *GCPAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{
		"provider":   ProviderName,
		"project_id": cfg.ProjectID,
		"auth_type":  "service_account_json",
	}
	var meta struct {
		ClientEmail  string `json:"client_email"`
		PrivateKeyID string `json:"private_key_id"`
		Type         string `json:"type"`
		ProjectID    string `json:"project_id"`
	}
	if err := json.Unmarshal([]byte(secrets.ServiceAccountJSON), &meta); err == nil {
		if meta.ClientEmail != "" {
			out["client_email"] = meta.ClientEmail
		}
		if meta.PrivateKeyID != "" {
			out["private_key_id"] = meta.PrivateKeyID
		}
		if meta.Type != "" {
			out["service_account_type"] = meta.Type
		}
		if meta.ProjectID != "" {
			out["service_account_project_id"] = meta.ProjectID
		}
	}
	return out, nil
}

var _ access.AccessConnector = (*GCPAccessConnector)(nil)
