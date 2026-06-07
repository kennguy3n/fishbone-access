package practice_fusion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// advanced-capability mapping for Practice Fusion /api/v1/users:
//
//   - ProvisionAccess  -> POST   /api/v1/users           (invite provider with role)
//   - RevokeAccess     -> DELETE /api/v1/users/{userId}  (remove provider)
//   - ListEntitlements -> GET    /api/v1/users/{userId}  (current role)
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Practice Fusion provider id or NPI / email
//   - grant.ResourceExternalID -> role slug ("admin", "provider", "staff")
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func practiceFusionValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("practice_fusion: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("practice_fusion: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *PracticeFusionAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("practice_fusion: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *PracticeFusionAccessConnector) usersURL() string {
	return c.baseURL() + "/api/v1/users"
}

func (c *PracticeFusionAccessConnector) userURL(userID string) string {
	return c.usersURL() + "/" + url.PathEscape(strings.TrimSpace(userID))
}

func (c *PracticeFusionAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if len(body) > 0 {
		rdr = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *PracticeFusionAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := practiceFusionValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"email": strings.TrimSpace(grant.UserExternalID),
		"role":  strings.TrimSpace(grant.ResourceExternalID),
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.usersURL(), payload)
	if err != nil {
		return err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentProvisionStatus(status, body):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("practice_fusion: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("practice_fusion: provision status %d: %s", status, string(body))
	}
}

func (c *PracticeFusionAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := practiceFusionValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, c.userURL(grant.UserExternalID), nil)
	if err != nil {
		return err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentRevokeStatus(status, body):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("practice_fusion: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("practice_fusion: revoke status %d: %s", status, string(body))
	}
}

func (c *PracticeFusionAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("practice_fusion: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.userURL(user), nil)
	if err != nil {
		return nil, err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("practice_fusion: list entitlements status %d: %s", status, string(body))
	}
	var resp struct {
		User struct {
			ID    string `json:"id"`
			Email string `json:"email"`
			Role  string `json:"role"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("practice_fusion: decode entitlements: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(resp.User.Email), user) &&
		strings.TrimSpace(resp.User.ID) != user {
		// Guard against the API returning a different user than requested
		// (e.g. id aliasing or a redirect), matching sibling connectors.
		return nil, nil
	}
	role := strings.TrimSpace(resp.User.Role)
	if role == "" {
		return []access.Entitlement{}, nil
	}
	return []access.Entitlement{{
		ResourceExternalID: role,
		Role:               role,
		Source:             "direct",
	}}, nil
}
