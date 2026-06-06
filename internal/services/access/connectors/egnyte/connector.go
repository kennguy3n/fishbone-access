// Package egnyte implements the access.AccessConnector contract for the
// Egnyte SCIM-compatible users API (/pubapi/v2/users).
//
// Egnyte exposes /pubapi/v1/userinfo for the *current* authenticated user
// and /pubapi/v2/users for the full user directory; the latter is the
// canonical pull source for ZTNA Teams. /pubapi/v1/userinfo is used as
// a cheap Connect probe so we exercise the credentials without fetching
// the full directory.
package egnyte

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
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName = "egnyte"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("egnyte: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Domain string `json:"domain"`
}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type EgnyteAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *EgnyteAccessConnector { return &EgnyteAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("egnyte: config is nil")
	}
	var cfg Config
	if v, ok := raw["domain"].(string); ok {
		cfg.Domain = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("egnyte: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_token"].(string); ok {
		s.AccessToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	domain := strings.TrimSpace(c.Domain)
	if domain == "" {
		return errors.New("egnyte: domain is required")
	}
	if !isDNSLabel(domain) {
		return errors.New("egnyte: domain must be a single DNS label (letters, digits, hyphen)")
	}
	return nil
}

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

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("egnyte: access_token is required")
	}
	return nil
}

func (c *EgnyteAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *EgnyteAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return fmt.Sprintf("https://%s.egnyte.com", strings.TrimSpace(cfg.Domain))
}

func (c *EgnyteAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *EgnyteAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *EgnyteAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *EgnyteAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("egnyte: %s %s: %w", req.Method, req.URL.Path, err)
	}
	return resp, nil
}

func (c *EgnyteAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("egnyte: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("egnyte: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *EgnyteAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *EgnyteAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL(cfg) + "/pubapi/v1/userinfo"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("egnyte: connect probe: %w", err)
	}
	return nil
}

func (c *EgnyteAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type egnyteUser struct {
	ID         json.Number `json:"id"`
	UserName   string      `json:"userName"`
	ExternalID string      `json:"externalId"`
	Active     bool        `json:"active"`
	Name       struct {
		GivenName  string `json:"givenName"`
		FamilyName string `json:"familyName"`
	} `json:"name"`
	Emails []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
}

type egnyteListResponse struct {
	TotalResults int          `json:"totalResults"`
	ItemsPerPage int          `json:"itemsPerPage"`
	StartIndex   int          `json:"startIndex"`
	Resources    []egnyteUser `json:"resources"`
}

func (c *EgnyteAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *EgnyteAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	offset := 1
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &offset)
		if offset < 1 {
			offset = 1
		}
	}
	base := c.baseURL(cfg)
	for {
		path := fmt.Sprintf("%s/pubapi/v2/users?startIndex=%d&count=%d", base, offset, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp egnyteListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("egnyte: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Resources))
		for _, u := range resp.Resources {
			email := ""
			for _, e := range u.Emails {
				if e.Primary || email == "" {
					email = e.Value
				}
			}
			display := strings.TrimSpace(u.Name.GivenName + " " + u.Name.FamilyName)
			if display == "" {
				display = u.UserName
			}
			if display == "" {
				display = email
			}
			status := "active"
			if !u.Active {
				status = "inactive"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID.String(),
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       email,
				Status:      status,
			})
		}
		next := ""
		if offset+len(resp.Resources) <= resp.TotalResults && len(resp.Resources) > 0 {
			next = fmt.Sprintf("%d", offset+pageSize)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset += pageSize
	}
}

// ---------- advanced capabilities ----------

type egnyteGroupMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
}

type egnyteGroup struct {
	ID          json.Number         `json:"id"`
	DisplayName string              `json:"displayName"`
	Members     []egnyteGroupMember `json:"members,omitempty"`
}

type egnyteGroupListResponse struct {
	StartIndex   int           `json:"startIndex"`
	ItemsPerPage int           `json:"itemsPerPage"`
	TotalResults int           `json:"totalResults"`
	Resources    []egnyteGroup `json:"resources"`
}

// ProvisionAccess adds a user to an Egnyte user group via SCIM-style
// PATCH on /pubapi/v2/groups/{groupId} with the standard add op. 409 or
// 200+"already exists" map to idempotent success.
func (c *EgnyteAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("egnyte: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("egnyte: grant.ResourceExternalID (groupId) is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload := map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]interface{}{{
			"op":    "add",
			"path":  "members",
			"value": []map[string]string{{"value": grant.UserExternalID}},
		}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("egnyte: marshal payload: %w", err)
	}
	fullURL := c.baseURL(cfg) + "/pubapi/v2/groups/" + url.PathEscape(grant.ResourceExternalID)
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPatch, fullURL, body)
	if err != nil {
		return err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusConflict:
		return nil
	case resp.StatusCode == http.StatusBadRequest && bytes.Contains(bytes.ToLower(respBody), []byte("already")):
		return nil
	default:
		return fmt.Errorf("egnyte: group PATCH status %d: %s", resp.StatusCode, string(respBody))
	}
}

// RevokeAccess removes a user from a group via SCIM PATCH remove.
// 404 means the group is gone ⇒ idempotent success.
func (c *EgnyteAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("egnyte: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("egnyte: grant.ResourceExternalID (groupId) is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload := map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]interface{}{{
			"op":   "remove",
			"path": fmt.Sprintf("members[value eq %q]", grant.UserExternalID),
		}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("egnyte: marshal payload: %w", err)
	}
	fullURL := c.baseURL(cfg) + "/pubapi/v2/groups/" + url.PathEscape(grant.ResourceExternalID)
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPatch, fullURL, body)
	if err != nil {
		return err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusNotFound:
		return nil
	case resp.StatusCode == http.StatusBadRequest && bytes.Contains(bytes.ToLower(respBody), []byte("no such member")):
		return nil
	default:
		return fmt.Errorf("egnyte: group PATCH status %d: %s", resp.StatusCode, string(respBody))
	}
}

// ListEntitlements pages /pubapi/v2/groups and filters group memberships
// for the given user. Each group with the user as a member produces an
// Entitlement.
func (c *EgnyteAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return nil, errors.New("egnyte: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	var out []access.Entitlement
	start := 1
	for {
		fullURL := fmt.Sprintf("%s/pubapi/v2/groups?startIndex=%d&count=%d", c.baseURL(cfg), start, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return nil, err
		}
		body, err := c.do(req)
		if err != nil {
			return nil, err
		}
		var resp egnyteGroupListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("egnyte: decode groups: %w", err)
		}
		for _, g := range resp.Resources {
			for _, m := range g.Members {
				if m.Value == userExternalID {
					out = append(out, access.Entitlement{
						ResourceExternalID: g.ID.String(),
						Role:               "member",
						Source:             "direct",
					})
					break
				}
			}
		}
		if resp.StartIndex+resp.ItemsPerPage > resp.TotalResults || resp.ItemsPerPage == 0 {
			return out, nil
		}
		start = resp.StartIndex + resp.ItemsPerPage
	}
}

// GetSSOMetadata returns Egnyte SAML federation metadata when the operator
// supplied an `sso_metadata_url` in configRaw. Returns nil (and nil error)
// when the config does not advertise a metadata URL so callers downgrade to
// access.ErrSSOFederationUnsupported.
func (c *EgnyteAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *EgnyteAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "oauth2",
		"token_short": shortToken(secrets.AccessToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return ""
	}
	if len(t) <= 8 {
		// Too short to reveal a prefix/suffix without exposing the whole
		// secret; emit a fixed mask so credential metadata never leaks
		// plaintext (GetCredentialsMetadata must not expose the secret).
		return "****"
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*EgnyteAccessConnector)(nil)
