package perimeter81

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

// advanced-capability mapping for Perimeter81 (Check Point Harmony Connect):
//
//   - ProvisionAccess  -> POST   /api/v1/users
//   - RevokeAccess     -> DELETE /api/v1/users/{id}
//   - ListEntitlements -> GET    /api/v1/users/{id}
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func perimeter81ValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("perimeter81: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("perimeter81: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *Perimeter81AccessConnector) usersURL() string {
	return c.baseURL() + "/api/v1/users"
}

func (c *Perimeter81AccessConnector) userURL(id string) string {
	return c.baseURL() + "/api/v1/users/" + url.PathEscape(strings.TrimSpace(id))
}

func (c *Perimeter81AccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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

func (c *Perimeter81AccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("perimeter81: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *Perimeter81AccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := perimeter81ValidateGrant(grant); err != nil {
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
		return fmt.Errorf("perimeter81: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("perimeter81: provision status %d: %s", status, string(body))
	}
}

func (c *Perimeter81AccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := perimeter81ValidateGrant(grant); err != nil {
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
		return fmt.Errorf("perimeter81: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("perimeter81: revoke status %d: %s", status, string(body))
	}
}

func (c *Perimeter81AccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("perimeter81: user external id is required")
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
		return nil, fmt.Errorf("perimeter81: list entitlements status %d: %s", status, string(body))
	}
	var resp struct {
		Email string `json:"email"`
		ID    string `json:"id"`
		Role  string `json:"role"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("perimeter81: decode entitlements: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(resp.Email), user) &&
		strings.TrimSpace(resp.ID) != user {
		return nil, nil
	}
	role := strings.TrimSpace(resp.Role)
	if role == "" {
		return []access.Entitlement{}, nil
	}
	return []access.Entitlement{{
		ResourceExternalID: role,
		Role:               role,
		Source:             "direct",
	}}, nil
}
