package vultr

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

// advanced-capability mapping for vultr:
//
//   - ProvisionAccess  -> POST   /v2/users
//   - RevokeAccess     -> DELETE /v2/users/{user_id}
//   - ListEntitlements -> GET    /v2/users
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Vultr user identifier (email)
//   - grant.ResourceExternalID -> ACL role token (subusers|billing|abuse|...)
//
// Bearer auth. Idempotent on (UserExternalID, ResourceExternalID).

func vultrValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("vultr: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("vultr: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *VultrAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("vultr: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *VultrAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.APIKey))
	return req, nil
}

func (c *VultrAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := vultrValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"email": strings.TrimSpace(grant.UserExternalID),
		"acls":  []string{strings.TrimSpace(grant.ResourceExternalID)},
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.baseURL()+"/v2/users", payload)
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
		return fmt.Errorf("vultr: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("vultr: provision status %d: %s", status, string(body))
	}
}

func (c *VultrAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := vultrValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := c.baseURL() + "/v2/users/" + url.PathEscape(strings.TrimSpace(grant.UserExternalID))
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
		return fmt.Errorf("vultr: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("vultr: revoke status %d: %s", status, string(body))
	}
}

func (c *VultrAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("vultr: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.baseURL()+"/v2/users", nil)
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
		return nil, fmt.Errorf("vultr: list entitlements status %d: %s", status, string(body))
	}
	var envelope struct {
		Users []struct {
			ID    string   `json:"id"`
			Email string   `json:"email"`
			ACL   []string `json:"acls"`
		} `json:"users"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("vultr: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0)
	for _, u := range envelope.Users {
		if u.ID != user && !strings.EqualFold(u.Email, user) {
			continue
		}
		for _, acl := range u.ACL {
			acl = strings.TrimSpace(acl)
			if acl == "" {
				continue
			}
			out = append(out, access.Entitlement{
				ResourceExternalID: acl,
				Role:               acl,
				Source:             "direct",
			})
		}
	}
	return out, nil
}
