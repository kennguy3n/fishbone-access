// Package box implements the access.AccessConnector contract for the
// Box users API.
package box

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
	ProviderName = "box"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("box: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type BoxAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *BoxAccessConnector { return &BoxAccessConnector{} }
func init()                    { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("box: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("box: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_token"].(string); ok {
		s.AccessToken = v
	}
	return s, nil
}

func (Config) validate() error { return nil }

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("box: access_token is required")
	}
	return nil
}

func (c *BoxAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *BoxAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.box.com"
}

func (c *BoxAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *BoxAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *BoxAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *BoxAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("box: %s %s: %w", req.Method, req.URL.Path, err)
	}
	return resp, nil
}

func (c *BoxAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("box: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("box: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *BoxAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *BoxAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/2.0/users/me"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("box: connect probe: %w", err)
	}
	return nil
}

func (c *BoxAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type boxUser struct {
	ID     string `json:"id"`
	Login  string `json:"login"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type boxResponse struct {
	TotalCount int       `json:"total_count"`
	Limit      int       `json:"limit"`
	Offset     int       `json:"offset"`
	Entries    []boxUser `json:"entries"`
}

func (c *BoxAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *BoxAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	offset := 0
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &offset)
		if offset < 0 {
			offset = 0
		}
	}
	base := c.baseURL()
	for {
		path := fmt.Sprintf("%s/2.0/users?limit=%d&offset=%d&user_type=all", base, pageSize, offset)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp boxResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("box: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Entries))
		for _, u := range resp.Entries {
			display := u.Name
			if display == "" {
				display = u.Login
			}
			status := "active"
			if u.Status != "" && !strings.EqualFold(u.Status, "active") {
				status = strings.ToLower(u.Status)
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Login,
				Status:      status,
			})
		}
		next := ""
		if offset+len(resp.Entries) < resp.TotalCount && len(resp.Entries) > 0 {
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

type boxCollaboration struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Role string `json:"role"`
	Item struct {
		ID   string `json:"id"`
		Type string `json:"type"`
		Name string `json:"name,omitempty"`
	} `json:"item"`
	AccessibleBy struct {
		ID    string `json:"id"`
		Login string `json:"login,omitempty"`
		Type  string `json:"type"`
	} `json:"accessible_by"`
}

type boxCollaborationsResponse struct {
	Entries    []boxCollaboration `json:"entries"`
	NextMarker string             `json:"next_marker,omitempty"`
	TotalCount int                `json:"total_count"`
}

func boxRole(grantRole string) string {
	switch strings.ToLower(strings.TrimSpace(grantRole)) {
	case "owner", "co-owner":
		return "co-owner"
	case "editor":
		return "editor"
	case "viewer", "":
		return "viewer"
	case "previewer":
		return "previewer"
	case "uploader":
		return "uploader"
	default:
		return strings.ToLower(strings.TrimSpace(grantRole))
	}
}

// ProvisionAccess creates a Box collaboration via POST /2.0/collaborations.
// ResourceExternalID is the folder ID, UserExternalID the Box user ID.
// 409 (user_already_collaborator) returns nil for idempotency.
func (c *BoxAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("box: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("box: grant.ResourceExternalID (folder id) is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload := map[string]interface{}{
		"item":          map[string]string{"type": "folder", "id": grant.ResourceExternalID},
		"accessible_by": map[string]string{"type": "user", "id": grant.UserExternalID},
		"role":          boxRole(grant.Role),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("box: marshal payload: %w", err)
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.baseURL()+"/2.0/collaborations", body)
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
	case resp.StatusCode == http.StatusBadRequest && bytes.Contains(bytes.ToLower(respBody), []byte("user_already_collaborator")):
		return nil
	default:
		return fmt.Errorf("box: collaborations POST status %d: %s", resp.StatusCode, string(respBody))
	}
}

// RevokeAccess deletes a Box collaboration. We first look up the
// collaboration that matches the (user, folder) pair, then DELETE it.
// 404 means the collaboration is already gone ⇒ idempotent success.
func (c *BoxAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("box: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("box: grant.ResourceExternalID (folder id) is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	collabID, err := c.findCollaborationID(ctx, secrets, grant.ResourceExternalID, grant.UserExternalID)
	if err != nil {
		return err
	}
	if collabID == "" {
		return nil
	}
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, c.baseURL()+"/2.0/collaborations/"+url.PathEscape(collabID))
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
		return fmt.Errorf("box: collaborations DELETE status %d: %s", resp.StatusCode, string(respBody))
	}
}

func (c *BoxAccessConnector) findCollaborationID(ctx context.Context, secrets Secrets, folderID, userID string) (string, error) {
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.baseURL()+"/2.0/folders/"+url.PathEscape(folderID)+"/collaborations")
	if err != nil {
		return "", err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("box: collaborations GET status %d: %s", resp.StatusCode, string(body))
	}
	var list boxCollaborationsResponse
	if err := json.Unmarshal(body, &list); err != nil {
		return "", fmt.Errorf("box: decode collaborations: %w", err)
	}
	for _, e := range list.Entries {
		if e.AccessibleBy.ID == userID || strings.EqualFold(e.AccessibleBy.Login, userID) {
			return e.ID, nil
		}
	}
	return "", nil
}

// ListEntitlements pages /2.0/users/{userId}/memberships (for group
// memberships) and emits an Entitlement per group. Box does not expose a
// per-user collaborations listing without enterprise admin scope; group
// membership is the closest universally available signal.
func (c *BoxAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return nil, errors.New("box: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.baseURL()+"/2.0/users/"+url.PathEscape(userExternalID)+"/memberships")
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Entries []struct {
			ID    string `json:"id"`
			Role  string `json:"role"`
			Group struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"group"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("box: decode memberships: %w", err)
	}
	out := make([]access.Entitlement, 0, len(resp.Entries))
	for _, e := range resp.Entries {
		if e.Group.ID == "" {
			continue
		}
		role := e.Role
		if role == "" {
			role = "member"
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: e.Group.ID,
			Role:               role,
			Source:             "direct",
		})
	}
	return out, nil
}

// GetSSOMetadata returns the operator-supplied SAML metadata URL if
// configured. Box federates SSO via SAML 2.0 from the Box Admin
// Console; when `sso_metadata_url` is blank the helper returns
// (nil, nil) and the caller gracefully downgrades.
func (c *BoxAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *BoxAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
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
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*BoxAccessConnector)(nil)
