package braze

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

// advanced-capability mapping for braze (SCIM v2):
//
//   - ProvisionAccess  -> POST   /scim/v2/Users
//                         body {userName, roles:[{value}]}
//   - RevokeAccess     -> DELETE /scim/v2/Users/{user_id}
//   - ListEntitlements -> GET    /scim/v2/Users/{user_id}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Braze SCIM user id
//                                 (we also accept email here and let the
//                                  server resolve via the SCIM filter)
//   - grant.ResourceExternalID -> SCIM role value (e.g. "Admin", "Member",
//                                 "Manager")
//
// Auth uses the SCIM bearer token (reusing the newRequest helper which
// sets "Accept: application/scim+json"). Idempotent on
// (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func brazeValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("braze: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("braze: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *BrazeAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("braze: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *BrazeAccessConnector) newSCIMRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if len(body) > 0 {
		rdr = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/scim+json")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

type scimRoleEntry struct {
	Value string `json:"value"`
}

type scimUserWithRoles struct {
	ID       string          `json:"id"`
	UserName string          `json:"userName"`
	Roles    []scimRoleEntry `json:"roles"`
	Emails   []scimEmail     `json:"emails"`
	Active   bool            `json:"active"`
}

func (c *BrazeAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := brazeValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": strings.TrimSpace(grant.UserExternalID),
		"roles": []scimRoleEntry{
			{Value: strings.TrimSpace(grant.ResourceExternalID)},
		},
	})
	endpoint := c.baseURL(cfg) + "/scim/v2/Users"
	req, err := c.newSCIMRequest(ctx, secrets, http.MethodPost, endpoint, payload)
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
		return fmt.Errorf("braze: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("braze: provision status %d: %s", status, string(body))
	}
}

func (c *BrazeAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := brazeValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := c.baseURL(cfg) + "/scim/v2/Users/" + url.PathEscape(strings.TrimSpace(grant.UserExternalID))
	req, err := c.newSCIMRequest(ctx, secrets, http.MethodDelete, endpoint, nil)
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
		return fmt.Errorf("braze: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("braze: revoke status %d: %s", status, string(body))
	}
}

func (c *BrazeAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("braze: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	endpoint := c.baseURL(cfg) + "/scim/v2/Users/" + url.PathEscape(user)
	req, err := c.newSCIMRequest(ctx, secrets, http.MethodGet, endpoint, nil)
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
		return nil, fmt.Errorf("braze: list entitlements status %d: %s", status, string(body))
	}
	var resp scimUserWithRoles
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("braze: decode user: %w", err)
	}
	out := make([]access.Entitlement, 0, len(resp.Roles))
	for _, r := range resp.Roles {
		role := strings.TrimSpace(r.Value)
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
