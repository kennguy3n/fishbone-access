package wordpress

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

// advanced-capability mapping for wordpress:
//
//   - ProvisionAccess  -> POST   /rest/v1.1/sites/{site}/users/new
//   - RevokeAccess     -> POST   /rest/v1.1/sites/{site}/users/{user_id}/delete
//   - ListEntitlements -> GET    /rest/v1.1/sites/{site}/users/{user_id}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> WordPress.com user login/id/email
//   - grant.ResourceExternalID -> role slug (e.g. "administrator","editor","author","contributor","subscriber")
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func wordpressValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("wordpress: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("wordpress: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *WordPressAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("wordpress: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *WordPressAccessConnector) usersBase(cfg Config) string {
	return c.baseURL() + "/rest/v1.1/sites/" + url.PathEscape(strings.TrimSpace(cfg.Site)) + "/users"
}

func (c *WordPressAccessConnector) inviteURL(cfg Config) string {
	return c.usersBase(cfg) + "/new"
}

func (c *WordPressAccessConnector) userURL(cfg Config, userID string) string {
	return c.usersBase(cfg) + "/" + url.PathEscape(strings.TrimSpace(userID))
}

func (c *WordPressAccessConnector) deleteURL(cfg Config, userID string) string {
	return c.userURL(cfg, userID) + "/delete"
}

func (c *WordPressAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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

func (c *WordPressAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := wordpressValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{
		"email": strings.TrimSpace(grant.UserExternalID),
		"role":  strings.TrimSpace(grant.ResourceExternalID),
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.inviteURL(cfg), payload)
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
		return fmt.Errorf("wordpress: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("wordpress: provision status %d: %s", status, string(body))
	}
}

func (c *WordPressAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := wordpressValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.deleteURL(cfg, grant.UserExternalID), nil)
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
		return fmt.Errorf("wordpress: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("wordpress: revoke status %d: %s", status, string(body))
	}
}

func (c *WordPressAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("wordpress: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.userURL(cfg, user), nil)
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
		return nil, fmt.Errorf("wordpress: list entitlements status %d: %s", status, string(body))
	}
	var m struct {
		ID    json.Number `json:"ID"`
		Login string      `json:"login"`
		Email string      `json:"email"`
		Roles []string    `json:"roles"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("wordpress: decode entitlements: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(m.Email), user) &&
		!strings.EqualFold(strings.TrimSpace(m.Login), user) &&
		strings.TrimSpace(m.ID.String()) != user {
		return nil, nil
	}
	out := make([]access.Entitlement, 0, len(m.Roles))
	for _, r := range m.Roles {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: r,
			Role:               r,
			Source:             "direct",
		})
	}
	return out, nil
}
