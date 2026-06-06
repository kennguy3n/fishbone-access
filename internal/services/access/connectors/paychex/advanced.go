package paychex

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

// advanced-capability mapping for Paychex:
//
//   - ProvisionAccess  -> PUT    /companies/{company_id}/workers/{worker_id}/assignments/{assignment_id}
//   - RevokeAccess     -> DELETE /companies/{company_id}/workers/{worker_id}/assignments/{assignment_id}
//   - ListEntitlements -> GET    /companies/{company_id}/workers/{worker_id}/assignments
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Paychex worker_id
//   - grant.ResourceExternalID -> Paychex assignment_id
//
// OAuth2 bearer auth via PaychexAccessConnector.newRequest.

func paychexValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("paychex: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("paychex: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *PaychexAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.doHTTP(req)
	if err != nil {
		return 0, nil, fmt.Errorf("paychex: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *PaychexAccessConnector) assignmentURL(cfg Config, userID, resID string) string {
	return fmt.Sprintf("%s/companies/%s/workers/%s/assignments/%s",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(cfg.CompanyID)),
		url.PathEscape(strings.TrimSpace(userID)),
		url.PathEscape(strings.TrimSpace(resID)))
}

func (c *PaychexAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := paychexValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodPut, c.assignmentURL(cfg, grant.UserExternalID, grant.ResourceExternalID))
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
		return fmt.Errorf("paychex: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("paychex: provision status %d: %s", status, string(body))
	}
}

func (c *PaychexAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := paychexValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, c.assignmentURL(cfg, grant.UserExternalID, grant.ResourceExternalID))
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
		return fmt.Errorf("paychex: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("paychex: revoke status %d: %s", status, string(body))
	}
}

func (c *PaychexAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("paychex: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/companies/%s/workers/%s/assignments",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(cfg.CompanyID)),
		url.PathEscape(user))
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
		return nil, fmt.Errorf("paychex: list assignments status %d: %s", status, string(body))
	}
	var envelope struct {
		Items []struct {
			ID   interface{} `json:"id"`
			Name string      `json:"name"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("paychex: decode assignments: %w", err)
	}
	out := make([]access.Entitlement, 0, len(envelope.Items))
	for _, r := range envelope.Items {
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
