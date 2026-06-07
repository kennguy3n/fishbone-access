package wazuh

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

// advanced-capability mapping for wazuh:
//
//   - ProvisionAccess  -> POST   /security/users/{user_id}/roles?role_ids={role_id}
//   - RevokeAccess     -> DELETE /security/users/{user_id}/roles?role_ids={role_id}
//   - ListEntitlements -> GET    /security/users/{user_id}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Wazuh user numeric ID
//   - grant.ResourceExternalID -> Wazuh role numeric ID
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func wazuhValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("wazuh: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("wazuh: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *WazuhAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("wazuh: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *WazuhAccessConnector) userRolesURL(cfg Config, userID, roleID string) string {
	return c.baseURL(cfg) + "/security/users/" + url.PathEscape(strings.TrimSpace(userID)) +
		"/roles?role_ids=" + url.QueryEscape(strings.TrimSpace(roleID))
}

func (c *WazuhAccessConnector) userURL(cfg Config, userID string) string {
	return c.baseURL(cfg) + "/security/users/" + url.PathEscape(strings.TrimSpace(userID))
}

func (c *WazuhAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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

func (c *WazuhAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := wazuhValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost,
		c.userRolesURL(cfg, grant.UserExternalID, grant.ResourceExternalID), nil)
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
		return fmt.Errorf("wazuh: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("wazuh: provision status %d: %s", status, string(body))
	}
}

func (c *WazuhAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := wazuhValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete,
		c.userRolesURL(cfg, grant.UserExternalID, grant.ResourceExternalID), nil)
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
		return fmt.Errorf("wazuh: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("wazuh: revoke status %d: %s", status, string(body))
	}
}

func (c *WazuhAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("wazuh: user external id is required")
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
		return nil, fmt.Errorf("wazuh: list entitlements status %d: %s", status, string(body))
	}
	var resp struct {
		Data struct {
			AffectedItems []struct {
				ID    json.Number   `json:"id"`
				Roles []json.Number `json:"roles"`
			} `json:"affected_items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("wazuh: decode entitlements: %w", err)
	}
	if len(resp.Data.AffectedItems) == 0 {
		return nil, nil
	}
	first := resp.Data.AffectedItems[0]
	if strings.TrimSpace(first.ID.String()) != user {
		return nil, nil
	}
	out := make([]access.Entitlement, 0, len(first.Roles))
	for _, r := range first.Roles {
		rid := strings.TrimSpace(r.String())
		if rid == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: rid,
			Role:               rid,
			Source:             "direct",
		})
	}
	return out, nil
}
