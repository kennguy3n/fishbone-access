package perplexity

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

// advanced-capability mapping for Perplexity:
//
//   - ProvisionAccess  -> POST   /api/v1/users           (invite user)
//   - RevokeAccess     -> DELETE /api/v1/users/{id}      (remove user)
//   - ListEntitlements -> GET    /api/v1/users/{id}      (current user + role)
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Perplexity user id or email
//   - grant.ResourceExternalID -> role slug ("owner", "admin", "member")
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func perplexityValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("perplexity: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("perplexity: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *PerplexityAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("perplexity: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *PerplexityAccessConnector) usersURL() string {
	return c.baseURL() + "/api/v1/users"
}

func (c *PerplexityAccessConnector) userURL(userID string) string {
	return c.baseURL() + "/api/v1/users/" + url.PathEscape(strings.TrimSpace(userID))
}

func (c *PerplexityAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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

func (c *PerplexityAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := perplexityValidateGrant(grant); err != nil {
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
		return fmt.Errorf("perplexity: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("perplexity: provision status %d: %s", status, string(body))
	}
}

func (c *PerplexityAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := perplexityValidateGrant(grant); err != nil {
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
		return fmt.Errorf("perplexity: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("perplexity: revoke status %d: %s", status, string(body))
	}
}

func (c *PerplexityAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("perplexity: user external id is required")
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
		return nil, fmt.Errorf("perplexity: list entitlements status %d: %s", status, string(body))
	}
	var resp struct {
		User struct {
			ID    string `json:"id"`
			Email string `json:"email"`
			Role  string `json:"role"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("perplexity: decode entitlements: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(resp.User.Email), user) &&
		strings.TrimSpace(resp.User.ID) != user {
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
