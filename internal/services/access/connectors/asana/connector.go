// Package asana implements the access.AccessConnector contract for the
// Asana workspace users API.
package asana

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
	ProviderName   = "asana"
	defaultBaseURL = "https://app.asana.com/api/1.0"
)

var ErrNotImplemented = fmt.Errorf("asana: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	WorkspaceGID string `json:"workspace_gid"`
}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type AsanaAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *AsanaAccessConnector { return &AsanaAccessConnector{} }
func init()                      { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("asana: config is nil")
	}
	var cfg Config
	if v, ok := raw["workspace_gid"].(string); ok {
		cfg.WorkspaceGID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("asana: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_token"].(string); ok {
		s.AccessToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.WorkspaceGID) == "" {
		return errors.New("asana: workspace_gid is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("asana: access_token is required")
	}
	return nil
}

func (c *AsanaAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *AsanaAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *AsanaAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *AsanaAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

// newJSONRequest is like newRequest but attaches a JSON body and the
// matching Content-Type header. Returns a request ready for c.client().Do.
func (c *AsanaAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, path string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

// doRaw issues a request and returns the *http.Response unchanged so the
// caller can dispatch on the status code (used for idempotent provision
// / revoke flows). Unlike do(), doRaw does NOT raise an error for non-2xx
// responses. Callers MUST close the returned body.
func (c *AsanaAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("asana: %s %s: %w", req.Method, req.URL.Path, err)
	}
	return resp, nil
}

func (c *AsanaAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("asana: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("asana: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *AsanaAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *AsanaAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/workspaces/"+cfg.WorkspaceGID)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("asana: connect probe: %w", err)
	}
	return nil
}

func (c *AsanaAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type asanaUsersResponse struct {
	Data     []asanaUser `json:"data"`
	NextPage struct {
		Offset string `json:"offset,omitempty"`
		Path   string `json:"path,omitempty"`
		URI    string `json:"uri,omitempty"`
	} `json:"next_page"`
}

type asanaUser struct {
	GID   string `json:"gid"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

func (c *AsanaAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *AsanaAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	offset := checkpoint
	for {
		path := "/workspaces/" + cfg.WorkspaceGID + "/users?limit=100&opt_fields=name,email"
		if offset != "" {
			path += "&offset=" + url.QueryEscape(offset)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp asanaUsersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("asana: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Data))
		for _, u := range resp.Data {
			display := u.Name
			if display == "" {
				display = u.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.GID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      "active",
			})
		}
		next := resp.NextPage.Offset
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset = next
	}
}

// ---------- advanced capabilities ----------

type asanaTeamMembership struct {
	GID  string `json:"gid"`
	Team struct {
		GID  string `json:"gid"`
		Name string `json:"name"`
	} `json:"team"`
}

type asanaTeamMembershipsResponse struct {
	Data     []asanaTeamMembership `json:"data"`
	NextPage struct {
		Offset string `json:"offset,omitempty"`
	} `json:"next_page"`
}

// addRemoveBody is the Asana convention of wrapping the actual payload
// under a top-level "data" object.
type addRemoveBody struct {
	Data struct {
		User string `json:"user"`
	} `json:"data"`
}

func buildAddRemovePayload(userExternalID string) ([]byte, error) {
	var payload addRemoveBody
	payload.Data.User = userExternalID
	return json.Marshal(payload)
}

// ProvisionAccess adds a user to an Asana team via
// POST /teams/{team_gid}/addUser. grant.ResourceExternalID = team GID.
// Asana returns 200 + the team-membership row on success, 403 with a body
// that mentions "already a member" when the user is already a member, and
// 404 when either the team or the user is unknown. We treat 403
// "already member" as idempotent success per docs/architecture.md §2.
func (c *AsanaAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("asana: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("asana: grant.ResourceExternalID is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body, err := buildAddRemovePayload(grant.UserExternalID)
	if err != nil {
		return fmt.Errorf("asana: marshal addUser payload: %w", err)
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, "/teams/"+url.PathEscape(grant.ResourceExternalID)+"/addUser", body)
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
	case resp.StatusCode == http.StatusForbidden && bytes.Contains(bytes.ToLower(respBody), []byte("already")):
		return nil
	case resp.StatusCode == http.StatusConflict:
		return nil
	default:
		return fmt.Errorf("asana: addUser status %d: %s", resp.StatusCode, string(respBody))
	}
}

// RevokeAccess removes a user from an Asana team via
// POST /teams/{team_gid}/removeUser. 404 (team or user gone) is treated
// as idempotent success.
func (c *AsanaAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("asana: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("asana: grant.ResourceExternalID is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body, err := buildAddRemovePayload(grant.UserExternalID)
	if err != nil {
		return fmt.Errorf("asana: marshal removeUser payload: %w", err)
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, "/teams/"+url.PathEscape(grant.ResourceExternalID)+"/removeUser", body)
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
		return fmt.Errorf("asana: removeUser status %d: %s", resp.StatusCode, string(respBody))
	}
}

// ListEntitlements pages /users/{user_gid}/team_memberships and emits one
// Entitlement per team membership. Asana exposes only the membership
// relation here; finer-grained roles are not surfaced.
func (c *AsanaAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return nil, errors.New("asana: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	var out []access.Entitlement
	offset := ""
	for {
		path := "/users/" + url.PathEscape(userExternalID) + "/team_memberships?limit=100&opt_fields=team.name"
		if offset != "" {
			path += "&offset=" + url.QueryEscape(offset)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return nil, err
		}
		body, err := c.do(req)
		if err != nil {
			return nil, err
		}
		var resp asanaTeamMembershipsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("asana: decode team_memberships: %w", err)
		}
		for _, tm := range resp.Data {
			out = append(out, access.Entitlement{
				ResourceExternalID: tm.Team.GID,
				Role:               "member",
				Source:             "direct",
			})
		}
		if resp.NextPage.Offset == "" {
			return out, nil
		}
		offset = resp.NextPage.Offset
	}
}
func (c *AsanaAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *AsanaAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":      ProviderName,
		"workspace_gid": cfg.WorkspaceGID,
		"auth_type":     "access_token",
		"token_short":   shortToken(secrets.AccessToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*AsanaAccessConnector)(nil)
