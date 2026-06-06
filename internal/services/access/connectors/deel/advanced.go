package deel

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

// advanced-capability mapping for Deel:
//
//   - ProvisionAccess  -> PUT    /rest/v2/people/{user}/roles/{role}
//   - RevokeAccess     -> DELETE /rest/v2/people/{user}/roles/{role}
//   - ListEntitlements -> GET    /rest/v2/people/{user}/roles
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Deel worker_id
//   - grant.ResourceExternalID -> Deel role_id
//
// Bearer auth via DeelAccessConnector.newRequest.

func deelValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("deel: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("deel: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *DeelAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("deel: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *DeelAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := deelValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/rest/v2/people/%s/roles/%s",
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
		return fmt.Errorf("deel: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("deel: provision status %d: %s", status, string(body))
	}
}

func (c *DeelAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := deelValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/rest/v2/people/%s/roles/%s",
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
		return fmt.Errorf("deel: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("deel: revoke status %d: %s", status, string(body))
	}
}

func (c *DeelAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("deel: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/rest/v2/people/%s/roles",
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
		return nil, fmt.Errorf("deel: list roles status %d: %s", status, string(body))
	}
	var roles []struct {
		ID   interface{} `json:"id"`
		Name string      `json:"name"`
	}
	if err := json.Unmarshal(body, &roles); err != nil {
		return nil, fmt.Errorf("deel: decode roles: %w", err)
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
