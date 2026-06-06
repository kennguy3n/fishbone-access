package xero

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

// advanced-capability mapping for Xero:
//
//   - ProvisionAccess  -> POST   /api.xro/2.0/Users/{userId}/roles/{role}
//   - RevokeAccess     -> DELETE /api.xro/2.0/Users/{userId}/roles/{role}
//   - ListEntitlements -> GET    /api.xro/2.0/Users/{userId}/roles
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Xero user GUID
//   - grant.ResourceExternalID -> Xero role id (e.g. "STANDARD", "ADVISOR")
//
// Bearer + Xero-Tenant-Id auth via XeroAccessConnector.newRequest.

func xeroValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("xero: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("xero: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *XeroAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("xero: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *XeroAccessConnector) roleURL(userID, resID string) string {
	return fmt.Sprintf("%s/api.xro/2.0/Users/%s/roles/%s",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(userID)),
		url.PathEscape(strings.TrimSpace(resID)))
}

func (c *XeroAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := xeroValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, cfg, secrets, http.MethodPost, c.roleURL(grant.UserExternalID, grant.ResourceExternalID))
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
		return fmt.Errorf("xero: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("xero: provision status %d: %s", status, string(body))
	}
}

func (c *XeroAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := xeroValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, cfg, secrets, http.MethodDelete, c.roleURL(grant.UserExternalID, grant.ResourceExternalID))
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
		return fmt.Errorf("xero: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("xero: revoke status %d: %s", status, string(body))
	}
}

func (c *XeroAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("xero: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/api.xro/2.0/Users/%s/roles",
		c.baseURL(),
		url.PathEscape(user))
	req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, endpoint)
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
		return nil, fmt.Errorf("xero: list roles status %d: %s", status, string(body))
	}
	var envelope struct {
		Roles []struct {
			ID   interface{} `json:"id"`
			Name string      `json:"name"`
		} `json:"roles"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("xero: decode roles: %w", err)
	}
	out := make([]access.Entitlement, 0, len(envelope.Roles))
	for _, r := range envelope.Roles {
		id := strings.TrimSpace(fmt.Sprintf("%v", r.ID))
		if id == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: id,
			Role:               strings.TrimSpace(r.Name),
			Source:             "direct",
		})
	}
	return out, nil
}
