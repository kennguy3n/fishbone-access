// Package cloudflare implements the access.AccessConnector contract for
// Cloudflare's account-members API.
//
// Capabilities:
//
//   - Validate (pure-local), Connect, VerifyPermissions
//
//   - CountIdentities, SyncIdentities (paginated /accounts/{id}/members)
//
//   - GetCredentialsMetadata (token metadata via /user/tokens/verify)
//
//   - GetSSOMetadata returns nil — Cloudflare itself federates via Access,
//     not via a generic IdP surface.
//
//   - ProvisionAccess / RevokeAccess / ListEntitlements: stubs.
package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"bytes"

	"net/url"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// ProviderName is the registry key for the Cloudflare connector.
const ProviderName = "cloudflare"

// ErrNotImplemented is returned by stubbed methods.
var ErrNotImplemented = fmt.Errorf("cloudflare: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

const defaultBaseURL = "https://api.cloudflare.com/client/v4"

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config is the operator-visible config.
type Config struct {
	AccountID string `json:"account_id"`
	Email     string `json:"email,omitempty"`
	// TeamDomain is the Cloudflare Access team name (e.g. "acme" for
	// https://acme.cloudflareaccess.com). When set, the connector
	// advertises Cloudflare Access SAML metadata via GetSSOMetadata.
	TeamDomain string `json:"team_domain,omitempty"`
}

// Secrets carries either an API token (preferred) or a legacy global API
// key paired with the account email.
type Secrets struct {
	APIToken string `json:"api_token,omitempty"`
	APIKey   string `json:"api_key,omitempty"`
}

// CloudflareAccessConnector implements access.AccessConnector.
type CloudflareAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

// New constructs a fresh connector instance.
func New() *CloudflareAccessConnector { return &CloudflareAccessConnector{} }

func init() { access.RegisterAccessConnector(ProviderName, New()) }

// ---------- Decode / Validate ----------

// DecodeConfig pulls a typed Config out of the operator-supplied payload.
func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("cloudflare: config is nil")
	}
	var cfg Config
	if v, ok := raw["account_id"].(string); ok {
		cfg.AccountID = v
	}
	if v, ok := raw["email"].(string); ok {
		cfg.Email = v
	}
	if v, ok := raw["team_domain"].(string); ok {
		cfg.TeamDomain = v
	}
	return cfg, nil
}

// DecodeSecrets pulls a typed Secrets out of the decrypted payload.
func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("cloudflare: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_token"].(string); ok {
		s.APIToken = v
	}
	if v, ok := raw["api_key"].(string); ok {
		s.APIKey = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.AccountID) == "" {
		return errors.New("cloudflare: account_id is required")
	}
	if team := strings.TrimSpace(c.TeamDomain); team != "" && !isDNSLabel(team) {
		return errors.New("cloudflare: team_domain must be a single DNS label (letters, digits, hyphen; no leading/trailing hyphen; \u226463 chars)")
	}
	return nil
}

// isDNSLabel reports whether s is a valid single DNS label (RFC 1035): 1–63
// chars of [A-Za-z0-9-], with no leading or trailing hyphen. Used to guard
// against injection into the team_domain URL interpolation in
// GetSSOMetadata (e.g. an operator-supplied "evil.com/" must be rejected).
func isDNSLabel(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return false
		}
	}
	return s[0] != '-' && s[len(s)-1] != '-'
}

func (s Secrets) validate(cfg Config) error {
	if strings.TrimSpace(s.APIToken) == "" && strings.TrimSpace(s.APIKey) == "" {
		return errors.New("cloudflare: api_token or api_key is required")
	}
	if strings.TrimSpace(s.APIToken) == "" && strings.TrimSpace(cfg.Email) == "" {
		return errors.New("cloudflare: email is required when authenticating with api_key")
	}
	return nil
}

func (c *CloudflareAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	_ = cfg
	_ = secrets
	return nil
}

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
	if err := s.validate(cfg); err != nil {
		return Config{}, Secrets{}, err
	}
	return cfg, s, nil
}

// ---------- HTTP plumbing ----------

func (c *CloudflareAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *CloudflareAccessConnector) newRequest(ctx context.Context, secrets Secrets, cfg Config, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(secrets.APIToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.APIToken))
	} else {
		req.Header.Set("X-Auth-Email", cfg.Email)
		req.Header.Set("X-Auth-Key", strings.TrimSpace(secrets.APIKey))
	}
	return req, nil
}

func (c *CloudflareAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("cloudflare: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *CloudflareAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// ---------- Connect / VerifyPermissions ----------

func (c *CloudflareAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, cfg, http.MethodGet, "/accounts/"+cfg.AccountID+"/members?per_page=1")
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("cloudflare: connect probe: %w", err)
	}
	return nil
}

func (c *CloudflareAccessConnector) VerifyPermissions(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	capabilities []string,
) ([]string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, cap := range capabilities {
		switch cap {
		case "sync_identity":
			req, err := c.newRequest(ctx, secrets, cfg, http.MethodGet, "/accounts/"+cfg.AccountID+"/members?per_page=1")
			if err != nil {
				missing = append(missing, fmt.Sprintf("sync_identity (%v)", err))
				continue
			}
			if _, err := c.do(req); err != nil {
				missing = append(missing, fmt.Sprintf("sync_identity (%v)", err))
			}
		default:
			missing = append(missing, fmt.Sprintf("%s (no probe defined)", cap))
		}
	}
	return missing, nil
}

// ---------- Identity sync ----------

type cfMembersResponse struct {
	Result     []cfMember `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		PerPage    int `json:"per_page"`
		TotalPages int `json:"total_pages"`
		Count      int `json:"count"`
		TotalCount int `json:"total_count"`
	} `json:"result_info"`
	Success bool             `json:"success"`
	Errors  []map[string]any `json:"errors"`
}

type cfMember struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	User   struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	} `json:"user"`
}

func (c *CloudflareAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	req, err := c.newRequest(ctx, secrets, cfg, http.MethodGet, "/accounts/"+cfg.AccountID+"/members?per_page=1")
	if err != nil {
		return 0, err
	}
	body, err := c.do(req)
	if err != nil {
		return 0, err
	}
	var resp cfMembersResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, fmt.Errorf("cloudflare: decode members: %w", err)
	}
	return resp.ResultInfo.TotalCount, nil
}

func (c *CloudflareAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	const perPage = 50
	page := 1
	if checkpoint != "" {
		if n, err := strconv.Atoi(checkpoint); err == nil && n > 0 {
			page = n
		}
	}
	for {
		path := fmt.Sprintf("/accounts/%s/members?per_page=%d&page=%d", cfg.AccountID, perPage, page)
		req, err := c.newRequest(ctx, secrets, cfg, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp cfMembersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("cloudflare: decode members: %w", err)
		}
		batch := mapMembers(resp.Result)
		nextCheckpoint := ""
		if resp.ResultInfo.TotalPages > page {
			nextCheckpoint = strconv.Itoa(page + 1)
		}
		if err := handler(batch, nextCheckpoint); err != nil {
			return err
		}
		if nextCheckpoint == "" {
			return nil
		}
		page++
	}
}

func mapMembers(in []cfMember) []*access.Identity {
	out := make([]*access.Identity, 0, len(in))
	for _, m := range in {
		display := strings.TrimSpace(m.User.FirstName + " " + m.User.LastName)
		if display == "" {
			display = m.User.Email
		}
		status := "active"
		if m.Status != "" && m.Status != "accepted" {
			status = m.Status
		}
		// Cloudflare's account-members CRUD endpoints (POST add-member,
		// GET/DELETE /accounts/{id}/members/{member_id}) all key off the
		// member ID (e.g. 4536bcfad5faccb...), which is distinct from
		// user.id (the user UUID) and is not stable across accounts.
		// Email is the only handle the operator-supplied JSON API will
		// accept directly on the Add Account Member POST, so we store the
		// email as ExternalID here and resolve the member ID at
		// Revoke/ListEntitlements time via findMemberIDByEmail.
		out = append(out, &access.Identity{
			ExternalID:  m.User.Email,
			Type:        access.IdentityTypeUser,
			DisplayName: display,
			Email:       m.User.Email,
			Status:      status,
		})
	}
	return out
}

// ---------- Stubs ----------

func (c *CloudflareAccessConnector) ProvisionAccess(
	ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant,
) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("cloudflare: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]interface{}{"email": grant.UserExternalID, "roles": []string{grant.ResourceExternalID}})
	req, err := c.newRequest(ctx, secrets, cfg, http.MethodPost, "/accounts/"+url.PathEscape(cfg.AccountID)+"/members")
	if err != nil {
		return err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare: provision: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		return nil
	}
	if strings.Contains(string(respBody), "already a member") {
		return nil
	}
	return fmt.Errorf("cloudflare: provision status %d: %s", resp.StatusCode, string(respBody))
}

func (c *CloudflareAccessConnector) RevokeAccess(
	ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant,
) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("cloudflare: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	memberID, err := c.findMemberIDByEmail(ctx, secrets, cfg, grant.UserExternalID)
	if err != nil {
		return err
	}
	if memberID == "" {
		// No member with this email — treat as idempotent success per
		// the 404/not-found-on-revoke contract.
		return nil
	}
	req, err := c.newRequest(ctx, secrets, cfg, http.MethodDelete, "/accounts/"+url.PathEscape(cfg.AccountID)+"/members/"+url.PathEscape(memberID))
	if err != nil {
		return err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare: revoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return fmt.Errorf("cloudflare: revoke status %d: %s", resp.StatusCode, string(respBody))
}

// findMemberIDByEmail paginates /accounts/{id}/members and returns the
// member-ID of the row whose user.email matches the supplied email
// (case-insensitive comparison). Returns ("", nil) when no row matches.
// This is the bridge between the email-based ExternalID stored by
// SyncIdentities and the member-ID URL segments that Cloudflare's
// member CRUD endpoints require.
func (c *CloudflareAccessConnector) findMemberIDByEmail(ctx context.Context, secrets Secrets, cfg Config, email string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(email))
	if normalized == "" {
		return "", nil
	}
	const perPage = 50
	page := 1
	for {
		path := fmt.Sprintf("/accounts/%s/members?per_page=%d&page=%d", cfg.AccountID, perPage, page)
		req, err := c.newRequest(ctx, secrets, cfg, http.MethodGet, path)
		if err != nil {
			return "", err
		}
		body, err := c.do(req)
		if err != nil {
			return "", fmt.Errorf("cloudflare: member lookup: %w", err)
		}
		var resp cfMembersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", fmt.Errorf("cloudflare: decode members: %w", err)
		}
		for _, m := range resp.Result {
			if strings.ToLower(strings.TrimSpace(m.User.Email)) == normalized {
				return m.ID, nil
			}
		}
		if resp.ResultInfo.TotalPages <= page {
			return "", nil
		}
		page++
	}
}

func (c *CloudflareAccessConnector) ListEntitlements(
	ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string,
) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("cloudflare: user external id is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	memberID, err := c.findMemberIDByEmail(ctx, secrets, cfg, userExternalID)
	if err != nil {
		return nil, err
	}
	if memberID == "" {
		return nil, nil
	}
	req, err := c.newRequest(ctx, secrets, cfg, http.MethodGet, "/accounts/"+url.PathEscape(cfg.AccountID)+"/members/"+url.PathEscape(memberID))
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: list entitlements: %w", err)
	}
	var resp struct {
		Result struct {
			Roles []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"roles"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("cloudflare: decode entitlements: %w", err)
	}
	var out []access.Entitlement
	for _, r := range resp.Result.Roles {
		out = append(out, access.Entitlement{
			ResourceExternalID: r.ID,
			Role:               r.Name,
			Source:             "direct",
		})
	}
	return out, nil
}

// GetSSOMetadata advertises Cloudflare Access SAML metadata when the
// connector is configured with a team_domain. Cloudflare publishes
// SAML metadata at
//
//	https://{team_domain}.cloudflareaccess.com/cdn-cgi/access/saml-metadata
//
// Wires into iam-core as a SAML IdP broker. Returns (nil, nil) when
// team_domain is not set so callers treat the connector as
// SSO-unsupported (ErrSSOFederationUnsupported).
func (c *CloudflareAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	team := strings.TrimSpace(cfg.TeamDomain)
	if team == "" {
		return nil, nil
	}
	if !isDNSLabel(team) {
		return nil, fmt.Errorf("cloudflare: team_domain %q is not a valid DNS label", team)
	}
	base := "https://" + team + ".cloudflareaccess.com"
	return &access.SSOMetadata{
		Protocol:    "saml",
		MetadataURL: base + "/cdn-cgi/access/saml-metadata",
		EntityID:    base,
		SSOLoginURL: base + "/cdn-cgi/access/sso",
	}, nil
}

// GetCredentialsMetadata returns token verification metadata from
// /user/tokens/verify when an API token is supplied; for legacy global
// API keys it returns just the email + auth_type.
func (c *CloudflareAccessConnector) GetCredentialsMetadata(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{
		"provider":   ProviderName,
		"account_id": cfg.AccountID,
	}
	if strings.TrimSpace(secrets.APIToken) == "" {
		out["auth_type"] = "api_key"
		out["email"] = cfg.Email
		return out, nil
	}
	out["auth_type"] = "api_token"
	req, err := c.newRequest(ctx, secrets, cfg, http.MethodGet, "/user/tokens/verify")
	if err != nil {
		return out, nil
	}
	body, err := c.do(req)
	if err != nil {
		return out, nil
	}
	var resp struct {
		Result struct {
			ID        string `json:"id"`
			Status    string `json:"status"`
			ExpiresOn string `json:"expires_on,omitempty"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err == nil {
		out["token_id"] = resp.Result.ID
		out["status"] = resp.Result.Status
		if resp.Result.ExpiresOn != "" {
			out["expires_on"] = resp.Result.ExpiresOn
		}
	}
	return out, nil
}

// Compile-time interface assertion.
var _ access.AccessConnector = (*CloudflareAccessConnector)(nil)
