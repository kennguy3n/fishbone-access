package meraki

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

// advanced-capability mapping for meraki:
//
//   - ProvisionAccess  -> POST   /api/v1/admins
//   - RevokeAccess     -> DELETE /api/v1/admins/{admin_id}
//   - ListEntitlements -> GET    /api/v1/admins/{admin_id}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Meraki dashboard admin id (email)
//   - grant.ResourceExternalID -> orgAccess slug (full|read-only|none|...)
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func merakiValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("meraki: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("meraki: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *MerakiAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("meraki: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *MerakiAccessConnector) adminsURL(orgID string) string {
	return c.baseURL() + "/api/v1/organizations/" + url.PathEscape(strings.TrimSpace(orgID)) + "/admins"
}

func (c *MerakiAccessConnector) adminURL(orgID, adminID string) string {
	return c.adminsURL(orgID) + "/" + url.PathEscape(strings.TrimSpace(adminID))
}

func (c *MerakiAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("X-Cisco-Meraki-API-Key", strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *MerakiAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := merakiValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{
		"email":     strings.TrimSpace(grant.UserExternalID),
		"orgAccess": strings.TrimSpace(grant.ResourceExternalID),
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.adminsURL(cfg.OrganizationID), payload)
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
		return fmt.Errorf("meraki: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("meraki: provision status %d: %s", status, string(body))
	}
}

func (c *MerakiAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := merakiValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, c.adminURL(cfg.OrganizationID, grant.UserExternalID), nil)
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
		return fmt.Errorf("meraki: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("meraki: revoke status %d: %s", status, string(body))
	}
}

func (c *MerakiAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("meraki: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.adminURL(cfg.OrganizationID, user), nil)
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
		return nil, fmt.Errorf("meraki: list entitlements status %d: %s", status, string(body))
	}
	var m struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		OrgAccess string `json:"orgAccess"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("meraki: decode entitlements: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(m.Email), user) &&
		strings.TrimSpace(m.ID) != user {
		return nil, nil
	}
	role := strings.TrimSpace(m.OrgAccess)
	if role == "" {
		return []access.Entitlement{}, nil
	}
	return []access.Entitlement{{
		ResourceExternalID: role,
		Role:               role,
		Source:             "direct",
	}}, nil
}
