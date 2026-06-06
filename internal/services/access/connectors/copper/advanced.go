package copper

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

// advanced-capability mapping for copper:
//
//   - ProvisionAccess  -> PUT    /developer_api/v1/users/{user_id}
//                         with {"role_id": "..."}
//   - RevokeAccess     -> DELETE /developer_api/v1/users/{user_id}/roles/{role_id}
//   - ListEntitlements -> GET    /developer_api/v1/users/{user_id}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Copper user id
//   - grant.ResourceExternalID -> role id
//
// Triple-header auth (X-PW-AccessToken / X-PW-Application /
// X-PW-UserEmail) reuses the existing connector.newRequest helper.
// Idempotent on (UserExternalID, ResourceExternalID).

func copperValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("copper: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("copper: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *CopperAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("copper: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *CopperAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("X-PW-AccessToken", strings.TrimSpace(secrets.APIKey))
	req.Header.Set("X-PW-Application", "developer_api")
	req.Header.Set("X-PW-UserEmail", strings.TrimSpace(secrets.Email))
	return req, nil
}

func (c *CopperAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := copperValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{"role_id": strings.TrimSpace(grant.ResourceExternalID)})
	endpoint := c.baseURL() + "/developer_api/v1/users/" + url.PathEscape(strings.TrimSpace(grant.UserExternalID))
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPut, endpoint, payload)
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
		return fmt.Errorf("copper: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("copper: provision status %d: %s", status, string(body))
	}
}

func (c *CopperAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := copperValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := c.baseURL() + "/developer_api/v1/users/" + url.PathEscape(strings.TrimSpace(grant.UserExternalID)) +
		"/roles/" + url.PathEscape(strings.TrimSpace(grant.ResourceExternalID))
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, endpoint, nil)
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
		return fmt.Errorf("copper: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("copper: revoke status %d: %s", status, string(body))
	}
}

func (c *CopperAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("copper: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	endpoint := c.baseURL() + "/developer_api/v1/users/" + url.PathEscape(user)
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, endpoint, nil)
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
		return nil, fmt.Errorf("copper: list entitlements status %d: %s", status, string(body))
	}
	var user1 struct {
		ID     interface{} `json:"id"`
		RoleID string      `json:"role_id"`
		Roles  []string    `json:"roles"`
	}
	if err := json.Unmarshal(body, &user1); err != nil {
		return nil, fmt.Errorf("copper: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0)
	roles := append([]string{}, user1.Roles...)
	if strings.TrimSpace(user1.RoleID) != "" {
		roles = append(roles, user1.RoleID)
	}
	for _, r := range roles {
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
