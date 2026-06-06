// Package trello implements the access.AccessConnector contract for the
// Trello organization members API.
package trello

import (
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
	ProviderName   = "trello"
	defaultBaseURL = "https://api.trello.com/1"
)

var ErrNotImplemented = fmt.Errorf("trello: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	OrganizationID string `json:"organization_id"`
}

type Secrets struct {
	APIKey   string `json:"api_key"`
	APIToken string `json:"api_token"`
}

type TrelloAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *TrelloAccessConnector { return &TrelloAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("trello: config is nil")
	}
	var cfg Config
	if v, ok := raw["organization_id"].(string); ok {
		cfg.OrganizationID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("trello: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_key"].(string); ok {
		s.APIKey = v
	}
	if v, ok := raw["api_token"].(string); ok {
		s.APIToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.OrganizationID) == "" {
		return errors.New("trello: organization_id is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIKey) == "" {
		return errors.New("trello: api_key is required")
	}
	if strings.TrimSpace(s.APIToken) == "" {
		return errors.New("trello: api_token is required")
	}
	return nil
}

func (c *TrelloAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *TrelloAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *TrelloAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *TrelloAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, path string, extra url.Values) (*http.Request, error) {
	u := c.baseURL() + path
	q := url.Values{}
	for k, vs := range extra {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	q.Set("key", strings.TrimSpace(secrets.APIKey))
	q.Set("token", strings.TrimSpace(secrets.APIToken))
	if strings.Contains(u, "?") {
		u += "&" + q.Encode()
	} else {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func (c *TrelloAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		// Trello requires api_key/api_token to be sent as URL query parameters
		// (no header-auth equivalent for personal tokens), so we strip the URL
		// component from any *url.Error before wrapping to keep credentials
		// out of the error chain (and therefore out of caller log lines).
		return nil, fmt.Errorf("trello: %s %s: %w", req.Method, req.URL.Path, sanitizeURLError(err))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("trello: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

// doRaw issues a request and returns the *http.Response unchanged so the
// caller can dispatch on the status code (idempotent provision / revoke).
func (c *TrelloAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("trello: %s %s: %w", req.Method, req.URL.Path, sanitizeURLError(err))
	}
	return resp, nil
}

func (c *TrelloAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *TrelloAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/organizations/"+cfg.OrganizationID, nil)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("trello: connect probe: %w", err)
	}
	return nil
}

func (c *TrelloAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type trelloMember struct {
	ID       string `json:"id"`
	FullName string `json:"fullName"`
	Username string `json:"username"`
	Type     string `json:"memberType,omitempty"`
}

func (c *TrelloAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

// Trello returns the full members list in one call (no pagination on this endpoint),
// but we still loop to honour the contract / be future-proof if Trello ever adds it.
func (c *TrelloAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/organizations/"+cfg.OrganizationID+"/members",
		url.Values{"fields": {"fullName,username"}})
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	var members []trelloMember
	if err := json.Unmarshal(body, &members); err != nil {
		return fmt.Errorf("trello: decode members: %w", err)
	}
	identities := make([]*access.Identity, 0, len(members))
	for _, m := range members {
		display := m.FullName
		if display == "" {
			display = m.Username
		}
		identities = append(identities, &access.Identity{
			ExternalID:  m.ID,
			Type:        access.IdentityTypeUser,
			DisplayName: display,
			Email:       "",
			Status:      "active",
		})
	}
	return handler(identities, "")
}

// ---------- advanced capabilities ----------

type trelloBoard struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func trelloMemberType(grantRole string) string {
	switch strings.ToLower(strings.TrimSpace(grantRole)) {
	case "admin":
		return "admin"
	case "observer":
		return "observer"
	default:
		return "normal"
	}
}

// ProvisionAccess adds a Trello member to a board via
// PUT /1/boards/{boardId}/members/{memberId}?type={role}. The Trello API
// is naturally idempotent (PUT with the same role is a no-op), so a 200
// response on a second call is treated as success.
func (c *TrelloAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("trello: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("trello: grant.ResourceExternalID (boardId) is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	extra := url.Values{}
	extra.Set("type", trelloMemberType(grant.Role))
	path := "/boards/" + url.PathEscape(grant.ResourceExternalID) + "/members/" + url.PathEscape(grant.UserExternalID)
	req, err := c.newRequest(ctx, secrets, http.MethodPut, path, extra)
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
	default:
		return fmt.Errorf("trello: board add member status %d: %s", resp.StatusCode, string(respBody))
	}
}

// RevokeAccess removes a Trello member from a board via
// DELETE /1/boards/{boardId}/members/{memberId}. 404 (board or member
// gone, or member not on the board) is treated as idempotent success.
func (c *TrelloAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("trello: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("trello: grant.ResourceExternalID (boardId) is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	path := "/boards/" + url.PathEscape(grant.ResourceExternalID) + "/members/" + url.PathEscape(grant.UserExternalID)
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, path, nil)
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
	default:
		return fmt.Errorf("trello: board remove member status %d: %s", resp.StatusCode, string(respBody))
	}
}

// ListEntitlements fetches /1/members/{memberId}/boards and emits one
// Entitlement per board the member belongs to. Trello returns the
// member's role per-board only on `/boards?fields=name,memberships`
// expand paths; for simplicity we use Role = "member" as the source role.
func (c *TrelloAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return nil, errors.New("trello: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	extra := url.Values{}
	extra.Set("fields", "id,name")
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/members/"+url.PathEscape(userExternalID)+"/boards", extra)
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var boards []trelloBoard
	if err := json.Unmarshal(body, &boards); err != nil {
		return nil, fmt.Errorf("trello: decode boards: %w", err)
	}
	out := make([]access.Entitlement, 0, len(boards))
	for _, b := range boards {
		out = append(out, access.Entitlement{
			ResourceExternalID: b.ID,
			Role:               "member",
			Source:             "direct",
		})
	}
	return out, nil
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker Trello
// (via Atlassian Access) SSO federation. When `sso_metadata_url` is blank
// the helper returns (nil, nil) and the caller gracefully downgrades.
func (c *TrelloAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *TrelloAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":        ProviderName,
		"organization_id": cfg.OrganizationID,
		"auth_type":       "api_key+token",
		"key_short":       shortToken(secrets.APIKey),
		"token_short":     shortToken(secrets.APIToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

// sanitizeURLError unwraps *url.Error and re-wraps with only the operation
// ("Get", "Post", ...) and the underlying error, dropping the URL field —
// which would otherwise embed the api_key/api_token query parameters in any
// log line that prints the returned error.
func sanitizeURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("%s: %w", urlErr.Op, urlErr.Err)
	}
	return err
}

var _ access.AccessConnector = (*TrelloAccessConnector)(nil)
