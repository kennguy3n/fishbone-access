package ghost

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

// advanced-capability mapping for Ghost:
//
//   - ProvisionAccess  -> POST   /ghost/api/admin/invites/             (invite member to a role)
//   - RevokeAccess     -> DELETE /ghost/api/admin/users/{id}/          (remove user)
//   - ListEntitlements -> GET    /ghost/api/admin/users/{id}/?include=roles
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Ghost user numeric id or email
//   - grant.ResourceExternalID -> role slug ("Administrator", "Editor", "Author", "Contributor")
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func ghostValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("ghost: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("ghost: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *GhostAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("ghost: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *GhostAccessConnector) invitesURL(cfg Config) string {
	return c.baseURL(cfg) + "/ghost/api/admin/invites/"
}

func (c *GhostAccessConnector) userURL(cfg Config, userID string) string {
	return c.baseURL(cfg) + "/ghost/api/admin/users/" + url.PathEscape(strings.TrimSpace(userID)) + "/"
}

func (c *GhostAccessConnector) userRolesURL(cfg Config, userID string) string {
	return c.baseURL(cfg) + "/ghost/api/admin/users/" + url.PathEscape(strings.TrimSpace(userID)) + "/?include=roles"
}

func (c *GhostAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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

func (c *GhostAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := ghostValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"invites": []map[string]interface{}{
			{
				"email": strings.TrimSpace(grant.UserExternalID),
				"role":  strings.TrimSpace(grant.ResourceExternalID),
			},
		},
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.invitesURL(cfg), payload)
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
		return fmt.Errorf("ghost: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("ghost: provision status %d: %s", status, string(body))
	}
}

func (c *GhostAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := ghostValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, c.userURL(cfg, grant.UserExternalID), nil)
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
		return fmt.Errorf("ghost: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("ghost: revoke status %d: %s", status, string(body))
	}
}

func (c *GhostAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("ghost: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.userRolesURL(cfg, user), nil)
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
		return nil, fmt.Errorf("ghost: list entitlements status %d: %s", status, string(body))
	}
	var resp struct {
		Users []struct {
			ID    string `json:"id"`
			Email string `json:"email"`
			Roles []struct {
				Name string `json:"name"`
			} `json:"roles"`
		} `json:"users"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("ghost: decode entitlements: %w", err)
	}
	if len(resp.Users) == 0 {
		return nil, nil
	}
	u := resp.Users[0]
	if !strings.EqualFold(strings.TrimSpace(u.Email), user) &&
		strings.TrimSpace(u.ID) != user {
		return nil, nil
	}
	out := make([]access.Entitlement, 0, len(u.Roles))
	for _, r := range u.Roles {
		role := strings.TrimSpace(r.Name)
		if role == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: role,
			Role:               role,
			Source:             "direct",
		})
	}
	return out, nil
}
