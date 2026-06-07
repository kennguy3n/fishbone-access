// Package figma implements the access.AccessConnector contract for the
// Figma team members API.
package figma

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
	ProviderName   = "figma"
	defaultBaseURL = "https://api.figma.com/v1"
)

var ErrNotImplemented = fmt.Errorf("figma: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	TeamID string `json:"team_id"`
}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type FigmaAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *FigmaAccessConnector { return &FigmaAccessConnector{} }
func init()                      { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("figma: config is nil")
	}
	var cfg Config
	if v, ok := raw["team_id"].(string); ok {
		cfg.TeamID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("figma: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_token"].(string); ok {
		s.AccessToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.TeamID) == "" {
		return errors.New("figma: team_id is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("figma: access_token is required")
	}
	return nil
}

func (c *FigmaAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *FigmaAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *FigmaAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *FigmaAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Figma-Token", strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *FigmaAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, path string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Figma-Token", strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

// doRaw issues a request and returns the *http.Response unchanged so the
// caller can dispatch on the status code (idempotent provision / revoke).
func (c *FigmaAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("figma: %s %s: %w", req.Method, req.URL.Path, err)
	}
	return resp, nil
}

func (c *FigmaAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("figma: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("figma: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *FigmaAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *FigmaAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/teams/"+url.PathEscape(cfg.TeamID)+"/projects")
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("figma: connect probe: %w", err)
	}
	return nil
}

func (c *FigmaAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type figmaTeamMembersResponse struct {
	Members []figmaMember `json:"members"`
	Cursor  struct {
		After string `json:"after,omitempty"`
	} `json:"cursor"`
}

// figmaProjectMembersResponse is the response type for
// GET /v1/projects/{project_id}/members. Figma's team and project
// member endpoints both return a top-level "members" array of objects
// with the same fields, but they are documented as separate endpoints
// with independently versioned schemas. We declare a distinct response
// type for the project endpoint so the shape contract is explicit
// per-endpoint — if Figma diverges the two in a future API release,
// only this type needs to change.
type figmaProjectMembersResponse struct {
	Members []figmaProjectMember `json:"members"`
}

type figmaMember struct {
	ID     string `json:"id"`
	Name   string `json:"handle"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	ImgURL string `json:"img_url,omitempty"`
}

// figmaProjectMember mirrors figmaMember but is scoped to the project
// members endpoint. Keeping it as a separate type guards against silent
// breakage if Figma ever ships a project-specific shape (e.g., adding
// project-scoped permission fields).
type figmaProjectMember struct {
	ID    string `json:"id"`
	Name  string `json:"handle"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

func (c *FigmaAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *FigmaAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	cursor := checkpoint
	for {
		path := "/teams/" + url.PathEscape(cfg.TeamID) + "/members"
		if cursor != "" {
			path += "?" + url.Values{"cursor": {cursor}}.Encode()
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp figmaTeamMembersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("figma: decode members: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Members))
		for _, m := range resp.Members {
			display := m.Name
			if display == "" {
				display = m.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  m.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       m.Email,
				Status:      "active",
			})
		}
		next := resp.Cursor.After
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}

// ---------- advanced capabilities ----------

type figmaProject struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type figmaProjectsResponse struct {
	Name     string         `json:"name"`
	Projects []figmaProject `json:"projects"`
}

func figmaRole(grantRole string) string {
	switch strings.ToLower(strings.TrimSpace(grantRole)) {
	case "editor", "edit":
		return "editor"
	case "owner":
		return "owner"
	case "viewer", "view", "":
		return "viewer"
	default:
		return strings.TrimSpace(grantRole)
	}
}

// ProvisionAccess shares a Figma project with a user via
// POST /v1/projects/{project_id}/members. ResourceExternalID is the
// project_id. 409 / already-member-style responses are idempotent.
func (c *FigmaAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("figma: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("figma: grant.ResourceExternalID (project_id) is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload := map[string]interface{}{
		"user_id": grant.UserExternalID,
		"role":    figmaRole(grant.Role),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("figma: marshal provision payload: %w", err)
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, "/projects/"+url.PathEscape(grant.ResourceExternalID)+"/members", body)
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
		return fmt.Errorf("figma: project member POST status %d: %s", resp.StatusCode, string(respBody))
	}
}

// RevokeAccess removes a user from a Figma project via
// DELETE /v1/projects/{project_id}/members/{user_id}. 404 is idempotent.
func (c *FigmaAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("figma: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("figma: grant.ResourceExternalID (project_id) is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, "/projects/"+url.PathEscape(grant.ResourceExternalID)+"/members/"+url.PathEscape(grant.UserExternalID))
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
		return fmt.Errorf("figma: project member DELETE status %d: %s", resp.StatusCode, string(respBody))
	}
}

// ListEntitlements walks /teams/{team_id}/projects and, for each
// project, fetches /projects/{project_id}/members and filters for the
// supplied user. Each matching membership emits a project-level
// Entitlement.
//
// Cost: this issues 1 request to list projects + 1 request per project.
// Figma has no per-user "my projects" endpoint, so this O(P) fan-out is
// inherent to the API surface. The loop honours ctx cancellation between
// per-project calls so long-running scans can be aborted promptly.
func (c *FigmaAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return nil, errors.New("figma: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/teams/"+url.PathEscape(cfg.TeamID)+"/projects")
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var resp figmaProjectsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("figma: decode projects: %w", err)
	}
	var out []access.Entitlement
	for _, p := range resp.Projects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		memReq, err := c.newRequest(ctx, secrets, http.MethodGet, "/projects/"+url.PathEscape(p.ID)+"/members")
		if err != nil {
			return nil, err
		}
		memBody, err := c.do(memReq)
		if err != nil {
			return nil, err
		}
		var mems figmaProjectMembersResponse
		if err := json.Unmarshal(memBody, &mems); err != nil {
			return nil, fmt.Errorf("figma: decode project members: %w", err)
		}
		for _, m := range mems.Members {
			if m.ID == userExternalID {
				role := strings.ToLower(m.Role)
				if role == "" {
					role = "viewer"
				}
				out = append(out, access.Entitlement{
					ResourceExternalID: p.ID,
					Role:               role,
					Source:             "direct",
				})
				break
			}
		}
	}
	return out, nil
}

// GetSSOMetadata returns Figma SAML federation metadata when the operator
// supplies `sso_metadata_url` (and optionally entity/login/logout URLs) in
// the connector config. Otherwise it returns nil so callers downgrade.
func (c *FigmaAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *FigmaAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"team_id":     cfg.TeamID,
		"auth_type":   "access_token",
		"token_short": shortToken(secrets.AccessToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*FigmaAccessConnector)(nil)
