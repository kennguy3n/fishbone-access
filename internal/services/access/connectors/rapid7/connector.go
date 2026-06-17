// Package rapid7 implements the access.AccessConnector contract for the
// Rapid7 InsightVM /api/3/ endpoints.
//
// InsightVM is a customer-installed Security Console reachable on an
// operator-controlled HTTPS host (typically `https://<console>:3780`).
// Authentication is HTTP Basic. Pagination uses query-string
// `page`/`size` and the JSON envelope contains `page.totalPages`.
//
// maps the advanced-capability methods as follows:
//
//   - ProvisionAccess  -> PUT    /api/3/sites/{siteId}/users/{userId}
//   - RevokeAccess     -> DELETE /api/3/sites/{siteId}/users/{userId}
//   - ListEntitlements -> GET    /api/3/users/{userId}/sites
//
// AccessGrant maps:
//   - grant.UserExternalID     -> userId (URL path)
//   - grant.ResourceExternalID -> siteId (URL path)
//   - grant.Role               -> recorded on the Entitlement, no role
//     assignment endpoint is exposed by /api/3/sites/{siteId}/users.
package rapid7

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName = "rapid7"
	pageSize     = 100
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	// Endpoint is the operator-controlled InsightVM Security Console URL
	// (e.g. https://insightvm.corp.example:3780). Required.
	Endpoint string `json:"endpoint"`
}

type Secrets struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Rapid7AccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *Rapid7AccessConnector { return &Rapid7AccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("rapid7: config is nil")
	}
	var cfg Config
	if v, ok := raw["endpoint"].(string); ok {
		cfg.Endpoint = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("rapid7: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["username"].(string); ok {
		s.Username = v
	}
	if v, ok := raw["password"].(string); ok {
		s.Password = v
	}
	return s, nil
}

func (c Config) validate() error {
	e := strings.TrimSpace(c.Endpoint)
	if e == "" {
		return errors.New("rapid7: endpoint is required")
	}
	u, err := url.Parse(e)
	if err != nil {
		return fmt.Errorf("rapid7: endpoint must be a well-formed URL: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("rapid7: endpoint must use https://")
	}
	if u.User != nil {
		return errors.New("rapid7: endpoint must not contain userinfo")
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("rapid7: endpoint must not contain a path")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("rapid7: endpoint must not contain a query or fragment")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("rapid7: endpoint must contain a host")
	}
	if net.ParseIP(host) != nil {
		return errors.New("rapid7: endpoint host must be a domain name, not an IP literal")
	}
	if !isHost(host) {
		return errors.New("rapid7: endpoint host must contain only DNS label characters and dots")
	}
	return nil
}

func isHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z':
			case r >= 'A' && r <= 'Z':
			case r >= '0' && r <= '9':
			case r == '-':
			default:
				return false
			}
		}
	}
	return true
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Username) == "" {
		return errors.New("rapid7: username is required")
	}
	if strings.TrimSpace(s.Password) == "" {
		return errors.New("rapid7: password is required")
	}
	return nil
}

func (c *Rapid7AccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *Rapid7AccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
}

func (c *Rapid7AccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Rapid7AccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	creds := strings.TrimSpace(secrets.Username) + ":" + strings.TrimSpace(secrets.Password)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *Rapid7AccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("rapid7: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("rapid7: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

// doRaw issues req and returns (status, body, err) without raising
// non-2xx as an error. ProvisionAccess / RevokeAccess use this so
// they can branch on the idempotency helpers from
// internal/services/access/idempotency.go.
func (c *Rapid7AccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("rapid7: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *Rapid7AccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *Rapid7AccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL(cfg) + "/api/3/users?page=0&size=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("rapid7: connect probe: %w", err)
	}
	return nil
}

func (c *Rapid7AccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type rapid7User struct {
	ID      json.Number `json:"id"`
	Login   string      `json:"login"`
	Email   string      `json:"email"`
	Name    string      `json:"name"`
	Enabled bool        `json:"enabled"`
}

type rapid7Page struct {
	Number     int `json:"number"`
	TotalPages int `json:"totalPages"`
}

type rapid7ListResponse struct {
	Resources []rapid7User `json:"resources"`
	Page      rapid7Page   `json:"page"`
}

func (c *Rapid7AccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *Rapid7AccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	page := 0
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &page)
		if page < 0 {
			page = 0
		}
	}
	base := c.baseURL(cfg)
	for {
		q := url.Values{
			"page": []string{fmt.Sprintf("%d", page)},
			"size": []string{fmt.Sprintf("%d", pageSize)},
		}
		fullURL := base + "/api/3/users?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp rapid7ListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("rapid7: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Resources))
		for _, u := range resp.Resources {
			display := strings.TrimSpace(u.Name)
			if display == "" {
				display = strings.TrimSpace(u.Login)
			}
			if display == "" {
				display = u.Email
			}
			status := "active"
			if !u.Enabled {
				status = "disabled"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID.String(),
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      status,
			})
		}
		next := ""
		if resp.Page.TotalPages > 0 && page+1 < resp.Page.TotalPages {
			next = fmt.Sprintf("%d", page+1)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		page++
	}
}

// validateGrantPair returns an error when grant is missing the
// (userId, siteId) pair Rapid7 requires.
func validateGrantPair(grant access.AccessGrant) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("rapid7: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("rapid7: grant.ResourceExternalID is required")
	}
	return nil
}

// ProvisionAccess associates the user with the supplied site via PUT
// /api/3/sites/{siteId}/users/{userId}. The endpoint is idempotent on
// the (siteId, userId) pair: re-running it after the user is already
// associated returns 200/204; some InsightVM versions return 409 with
// an "already exists" envelope, which IsIdempotentProvisionStatus
// recognises as success per docs/architecture.md §2.
func (c *Rapid7AccessConnector) ProvisionAccess(
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
	path := fmt.Sprintf("/api/3/sites/%s/users/%s",
		url.PathEscape(strings.TrimSpace(grant.ResourceExternalID)),
		url.PathEscape(strings.TrimSpace(grant.UserExternalID)))
	req, err := c.newRequest(ctx, secrets, http.MethodPut, c.baseURL(cfg)+path)
	if err != nil {
		return err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return fmt.Errorf("rapid7: provision request: %w", err)
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentProvisionStatus(status, body):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("rapid7: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("rapid7: provision status %d: %s", status, string(body))
	}
}

// RevokeAccess disassociates the user from the supplied site via
// DELETE /api/3/sites/{siteId}/users/{userId}. 404 / "not found"
// responses are treated as idempotent success per docs/architecture.md §2.
func (c *Rapid7AccessConnector) RevokeAccess(
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
	path := fmt.Sprintf("/api/3/sites/%s/users/%s",
		url.PathEscape(strings.TrimSpace(grant.ResourceExternalID)),
		url.PathEscape(strings.TrimSpace(grant.UserExternalID)))
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, c.baseURL(cfg)+path)
	if err != nil {
		return err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return fmt.Errorf("rapid7: revoke request: %w", err)
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentRevokeStatus(status, body):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("rapid7: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("rapid7: revoke status %d: %s", status, string(body))
	}
}

// ListEntitlements pages through GET /api/3/users/{userId}/sites and
// surfaces each site as an Entitlement{ResourceExternalID: siteID,
// Role: siteName, Source: "direct"}.
func (c *Rapid7AccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("rapid7: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	base := c.baseURL(cfg)
	page := 0
	var out []access.Entitlement
	for {
		q := url.Values{
			"page": []string{fmt.Sprintf("%d", page)},
			"size": []string{fmt.Sprintf("%d", pageSize)},
		}
		fullURL := fmt.Sprintf("%s/api/3/users/%s/sites?%s", base, url.PathEscape(user), q.Encode())
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return nil, err
		}
		body, err := c.do(req)
		if err != nil {
			return nil, err
		}
		var resp rapid7SitesResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("rapid7: decode user sites: %w", err)
		}
		for _, s := range resp.Resources {
			out = append(out, access.Entitlement{
				ResourceExternalID: s.ID.String(),
				Role:               s.Name,
				Source:             "direct",
			})
		}
		if resp.Page.TotalPages == 0 || page+1 >= resp.Page.TotalPages {
			return out, nil
		}
		page++
	}
}

type rapid7Site struct {
	ID   json.Number `json:"id"`
	Name string      `json:"name"`
}

type rapid7SitesResponse struct {
	Resources []rapid7Site `json:"resources"`
	Page      rapid7Page   `json:"page"`
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker Rapid7
// InsightVM / InsightIDR SSO federation. When `sso_metadata_url` is blank
// the helper returns (nil, nil) and the caller gracefully downgrades.
func (c *Rapid7AccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *Rapid7AccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":       ProviderName,
		"auth_type":      "basic",
		"username_short": shortToken(secrets.Username),
		"password_short": shortToken(secrets.Password),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*Rapid7AccessConnector)(nil)
