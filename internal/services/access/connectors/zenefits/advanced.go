package zenefits

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

// advanced-capability mapping for Zenefits (TriNet HR):
//
//   - ProvisionAccess  -> PUT    /core/people/{user}/roles/{role}
//   - RevokeAccess     -> DELETE /core/people/{user}/roles/{role}
//   - ListEntitlements -> GET    /core/people/{user}/roles
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Zenefits person_id
//   - grant.ResourceExternalID -> Zenefits role_id
//
// Bearer auth via ZenefitsAccessConnector.newRequest.

func zenefitsValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("zenefits: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("zenefits: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *ZenefitsAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("zenefits: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *ZenefitsAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := zenefitsValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/core/people/%s/roles/%s",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(grant.UserExternalID)),
		url.PathEscape(strings.TrimSpace(grant.ResourceExternalID)))
	req, err := c.newRequest(ctx, secrets, http.MethodPut, endpoint)
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
		return fmt.Errorf("zenefits: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("zenefits: provision status %d: %s", status, string(body))
	}
}

func (c *ZenefitsAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := zenefitsValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/core/people/%s/roles/%s",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(grant.UserExternalID)),
		url.PathEscape(strings.TrimSpace(grant.ResourceExternalID)))
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, endpoint)
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
		return fmt.Errorf("zenefits: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("zenefits: revoke status %d: %s", status, string(body))
	}
}

func (c *ZenefitsAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("zenefits: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/core/people/%s/roles",
		c.baseURL(), url.PathEscape(user))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, endpoint)
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
		return nil, fmt.Errorf("zenefits: list roles status %d: %s", status, string(body))
	}
	var roles []struct {
		ID   interface{} `json:"id"`
		Name string      `json:"name"`
	}
	if err := json.Unmarshal(body, &roles); err != nil {
		return nil, fmt.Errorf("zenefits: decode roles: %w", err)
	}
	out := make([]access.Entitlement, 0, len(roles))
	for _, r := range roles {
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
