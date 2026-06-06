// Package auth0 implements the access.AccessConnector contract for Auth0.
//
// Capabilities:
//
//   - Validate (pure-local), Connect, VerifyPermissions
//   - CountIdentities, SyncIdentities (paginated /api/v2/users)
//   - SyncIdentitiesDelta (Auth0 logs API; 400 with "expired log_id" → ErrDeltaTokenExpired)
//   - GetSSOMetadata (Auth0 OIDC discovery URL)
//   - GetCredentialsMetadata
//   - ProvisionAccess / RevokeAccess / ListEntitlements: real
//     implementations against /api/v2/users/{userId}/roles.
package auth0

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// ErrNotImplemented is retained for any future capability that is not yet
// implemented; ProvisionAccess / RevokeAccess / ListEntitlements no longer
// return it now that the advanced capabilities are implemented.
var ErrNotImplemented = fmt.Errorf("auth0: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Auth0AccessConnector implements access.AccessConnector and
// access.IdentityDeltaSyncer.
type Auth0AccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string // optional base URL override (e.g. http://127.0.0.1:port) for tests
}

// New returns a fresh connector instance.
func New() *Auth0AccessConnector {
	return &Auth0AccessConnector{}
}

// ---------- Validate / Connect / VerifyPermissions ----------

func (c *Auth0AccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *Auth0AccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return fmt.Errorf("auth0: connect token: %w", err)
	}
	req, err := c.newAuthedRequest(ctx, cfg, token, http.MethodGet, "/api/v2/users?per_page=1", nil)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("auth0: connect probe: %w", err)
	}
	return nil
}

// VerifyPermissions probes /api/v2/users?per_page=1 for the sync_identity
// capability. Other capabilities are reported as missing-with-no-probe
// (matches the Okta pattern).
func (c *Auth0AccessConnector) VerifyPermissions(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	capabilities []string,
) ([]string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return nil, fmt.Errorf("auth0: authenticate: %w", err)
	}
	var missing []string
	for _, cap := range capabilities {
		switch cap {
		case "sync_identity":
			req, err := c.newAuthedRequest(ctx, cfg, token, http.MethodGet, "/api/v2/users?per_page=1", nil)
			if err != nil {
				return nil, err
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

// CountIdentities calls /api/v2/users?per_page=1&include_totals=true and
// reads the "total" field. include_totals slows the endpoint at large user
// counts but is fine for a one-shot count probe.
func (c *Auth0AccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return 0, fmt.Errorf("auth0: authenticate: %w", err)
	}
	req, err := c.newAuthedRequest(ctx, cfg, token, http.MethodGet, "/api/v2/users?per_page=1&include_totals=true", nil)
	if err != nil {
		return 0, err
	}
	body, err := c.do(req)
	if err != nil {
		return 0, err
	}
	var totals struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(body, &totals); err != nil {
		return 0, fmt.Errorf("auth0: decode totals: %w", err)
	}
	return totals.Total, nil
}

// SyncIdentities pages through /api/v2/users using page-number pagination
// (Auth0's preferred mode). The checkpoint is the next page index encoded
// as a decimal string; an empty checkpoint starts at page 0.
func (c *Auth0AccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return fmt.Errorf("auth0: authenticate: %w", err)
	}

	page := 0
	if checkpoint != "" {
		if n, err := strconv.Atoi(checkpoint); err == nil {
			page = n
		}
	}
	const perPage = 100

	for {
		path := fmt.Sprintf("/api/v2/users?per_page=%d&page=%d", perPage, page)
		req, err := c.newAuthedRequest(ctx, cfg, token, http.MethodGet, path, nil)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var users []auth0User
		if err := json.Unmarshal(body, &users); err != nil {
			return fmt.Errorf("auth0: decode users: %w", err)
		}

		batch := mapAuth0Users(users)
		nextCheckpoint := ""
		if len(users) == perPage {
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

// SyncIdentitiesDelta polls Auth0's /api/v2/logs endpoint and emits user
// lifecycle events (`ss` signup, `sapi` signup via API, `fu`/`fui` user
// updates). On 400 with an expired log_id message Auth0 surfaces a
// distinctive error body; we translate that to access.ErrDeltaTokenExpired
// so the caller drops the stored cursor and falls back to full sync.
func (c *Auth0AccessConnector) SyncIdentitiesDelta(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	deltaLink string,
	handler func(batch []*access.Identity, removedExternalIDs []string, nextLink string) error,
) (string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return "", err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return "", fmt.Errorf("auth0: authenticate: %w", err)
	}

	from := deltaLink
	const take = 100

	var finalDeltaLink string
	for {
		path := fmt.Sprintf("/api/v2/logs?take=%d", take)
		if from != "" {
			path = fmt.Sprintf("%s&from=%s", path, url.QueryEscape(from))
		}
		req, err := c.newAuthedRequest(ctx, cfg, token, http.MethodGet, path, nil)
		if err != nil {
			return "", err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return "", err
		}
		switch resp.StatusCode {
		case http.StatusOK:
			// fallthrough
		case http.StatusBadRequest, http.StatusGone:
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			if isExpiredCursorBody(body) {
				return "", access.ErrDeltaTokenExpired
			}
			if resp.StatusCode == http.StatusGone {
				return "", access.ErrDeltaTokenExpired
			}
			return "", fmt.Errorf("auth0: logs status %d: %s", resp.StatusCode, string(body))
		default:
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			return "", fmt.Errorf("auth0: logs status %d: %s", resp.StatusCode, string(body))
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return "", err
		}
		var events []auth0LogEvent
		if err := json.Unmarshal(body, &events); err != nil {
			return "", fmt.Errorf("auth0: decode logs: %w", err)
		}
		batch, removed := mapAuth0LogEvents(events)
		nextFrom := ""
		if len(events) == take {
			nextFrom = events[len(events)-1].LogID
		}
		if err := handler(batch, removed, nextFrom); err != nil {
			return "", err
		}
		if nextFrom == "" {
			if len(events) > 0 {
				finalDeltaLink = events[len(events)-1].LogID
			} else {
				finalDeltaLink = from
			}
			return finalDeltaLink, nil
		}
		from = nextFrom
	}
}

// InitialDeltaCursor returns the log_id of the most recent log
// entry as a "now" baseline. SyncIdentitiesDelta passes it back as
// `from=<log_id>`, which Auth0 interprets as "logs strictly after
// this entry" — exactly the events-since-now semantics the
// orchestrator needs. One small API call (`take=1&sort=date:-1`).
// If the tenant has no logs at all the response is empty; in that
// case we return an empty cursor so the orchestrator stays in
// full-sync mode until logs arrive.
func (c *Auth0AccessConnector) InitialDeltaCursor(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
) (string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return "", err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return "", fmt.Errorf("auth0: authenticate: %w", err)
	}
	req, err := c.newAuthedRequest(ctx, cfg, token, http.MethodGet, "/api/v2/logs?take=1&sort=date:-1", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return "", err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth0: initial delta probe status %d: %s", resp.StatusCode, string(body))
	}
	var events []auth0LogEvent
	if err := json.Unmarshal(body, &events); err != nil {
		return "", fmt.Errorf("auth0: decode initial delta probe: %w", err)
	}
	if len(events) == 0 {
		return "", nil
	}
	return events[0].LogID, nil
}

// ---------- advanced capabilities ----------

// ProvisionAccess assigns roles to a user via POST /api/v2/users/{userId}/roles.
// 409 Conflict on assign is treated as idempotent success.
func (c *Auth0AccessConnector) ProvisionAccess(
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
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return fmt.Errorf("auth0: authenticate: %w", err)
	}
	body, err := json.Marshal(map[string][]string{"roles": {grant.ResourceExternalID}})
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/api/v2/users/%s/roles", url.PathEscape(grant.UserExternalID))
	req, err := c.newAuthedRequest(ctx, cfg, token, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.doRaw(req)
	if err != nil {
		return fmt.Errorf("auth0: provision request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent, http.StatusConflict:
		return nil
	default:
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("auth0: provision status %d: %s", resp.StatusCode, string(rb))
	}
}

// RevokeAccess removes roles from a user via DELETE /api/v2/users/{userId}/roles
// (with body {"roles": [...]}). 404 is idempotent success.
func (c *Auth0AccessConnector) RevokeAccess(
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
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return fmt.Errorf("auth0: authenticate: %w", err)
	}
	body, err := json.Marshal(map[string][]string{"roles": {grant.ResourceExternalID}})
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/api/v2/users/%s/roles", url.PathEscape(grant.UserExternalID))
	req, err := c.newAuthedRequest(ctx, cfg, token, http.MethodDelete, path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.doRaw(req)
	if err != nil {
		return fmt.Errorf("auth0: revoke request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	default:
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("auth0: revoke status %d: %s", resp.StatusCode, string(rb))
	}
}

// ListEntitlements pages through /api/v2/users/{userExternalID}/roles. Roles
// surface as Entitlement{ResourceExternalID: roleID, Role: roleName,
// Source: "direct"}.
func (c *Auth0AccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("auth0: user external id is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return nil, fmt.Errorf("auth0: authenticate: %w", err)
	}

	const perPage = 100
	page := 0
	var out []access.Entitlement
	for {
		path := fmt.Sprintf("/api/v2/users/%s/roles?per_page=%d&page=%d",
			url.PathEscape(userExternalID), perPage, page)
		req, err := c.newAuthedRequest(ctx, cfg, token, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		body, err := c.do(req)
		if err != nil {
			return nil, err
		}
		var roles []auth0Role
		if err := json.Unmarshal(body, &roles); err != nil {
			return nil, fmt.Errorf("auth0: decode roles: %w", err)
		}
		for _, r := range roles {
			out = append(out, access.Entitlement{
				ResourceExternalID: r.ID,
				Role:               r.Name,
				Source:             "direct",
			})
		}
		if len(roles) < perPage {
			return out, nil
		}
		page++
	}
}

func validateGrantPair(grant access.AccessGrant) error {
	if grant.UserExternalID == "" {
		return errors.New("auth0: grant.UserExternalID is required")
	}
	if grant.ResourceExternalID == "" {
		return errors.New("auth0: grant.ResourceExternalID is required")
	}
	return nil
}

type auth0Role struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ---------- Metadata ----------

func (c *Auth0AccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	domain := cfg.normalised()
	return &access.SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: fmt.Sprintf("https://%s/.well-known/openid-configuration", domain),
		EntityID:    fmt.Sprintf("https://%s/", domain),
		SSOLoginURL: fmt.Sprintf("https://%s/authorize", domain),
	}, nil
}

func (c *Auth0AccessConnector) GetCredentialsMetadata(_ context.Context, _, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
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
		"note":      "client secret expiry not exposed by Auth0 API",
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

func (c *Auth0AccessConnector) absURL(cfg Config, path string) string {
	if c.urlOverride != "" {
		return c.urlOverride + path
	}
	return "https://" + cfg.normalised() + path
}

// fetchAccessToken obtains a Management API access token via the Auth0
// /oauth/token client_credentials flow.
func (c *Auth0AccessConnector) fetchAccessToken(ctx context.Context, cfg Config, secrets Secrets) (string, error) {
	body := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     secrets.ClientID,
		"client_secret": secrets.ClientSecret,
		"audience":      fmt.Sprintf("https://%s/api/v2/", cfg.normalised()),
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.absURL(cfg, "/oauth/token"), bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	respBody, err := c.do(req)
	if err != nil {
		return "", err
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(respBody, &tok); err != nil {
		return "", fmt.Errorf("auth0: decode token: %w", err)
	}
	if tok.AccessToken == "" {
		return "", errors.New("auth0: token response missing access_token")
	}
	return tok.AccessToken, nil
}

func (c *Auth0AccessConnector) newAuthedRequest(ctx context.Context, cfg Config, token, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.absURL(cfg, path), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func (c *Auth0AccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("auth0: %s status %d: %s", req.URL.Path, resp.StatusCode, string(body))
	}
	return io.ReadAll(resp.Body)
}

func (c *Auth0AccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	if c.httpClient != nil {
		return c.httpClient().Do(req)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

func isExpiredCursorBody(body []byte) bool {
	s := strings.ToLower(string(body))
	return strings.Contains(s, "expired") ||
		strings.Contains(s, "log_id") && strings.Contains(s, "invalid") ||
		strings.Contains(s, "out of retention")
}

func mapAuth0Users(users []auth0User) []*access.Identity {
	out := make([]*access.Identity, 0, len(users))
	for _, u := range users {
		status := "active"
		if u.Blocked {
			status = "disabled"
		}
		out = append(out, &access.Identity{
			ExternalID:  u.UserID,
			Type:        access.IdentityTypeUser,
			DisplayName: u.Name,
			Email:       u.Email,
			Status:      status,
		})
	}
	return out
}

func mapAuth0LogEvents(events []auth0LogEvent) ([]*access.Identity, []string) {
	identities := make([]*access.Identity, 0, len(events))
	var removed []string
	for _, e := range events {
		if e.UserID == "" {
			continue
		}
		switch e.Type {
		case "ss", "sapi", "fu", "fui":
			identities = append(identities, &access.Identity{
				ExternalID: e.UserID,
				Type:       access.IdentityTypeUser,
				Email:      e.UserName,
				Status:     "active",
			})
		case "du", "dud":
			removed = append(removed, e.UserID)
		}
	}
	return identities, removed
}

// ---------- Auth0 DTOs ----------

type auth0User struct {
	UserID  string `json:"user_id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Blocked bool   `json:"blocked"`
}

type auth0LogEvent struct {
	LogID    string `json:"log_id"`
	Type     string `json:"type"`
	Date     string `json:"date"`
	UserID   string `json:"user_id"`
	UserName string `json:"user_name"`
}

// ---------- compile-time interface assertions ----------

var (
	_ access.AccessConnector     = (*Auth0AccessConnector)(nil)
	_ access.IdentityDeltaSyncer = (*Auth0AccessConnector)(nil)
)
