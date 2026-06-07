package gusto

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

// advanced-capability mapping for Gusto:
//
//   - ProvisionAccess  -> PUT    /v1/companies/{company_id}/employees/{user}/jobs/{job}
//   - RevokeAccess     -> DELETE /v1/companies/{company_id}/employees/{user}/jobs/{job}
//   - ListEntitlements -> GET    /v1/companies/{company_id}/employees/{user}/jobs
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Gusto employee_id
//   - grant.ResourceExternalID -> Gusto job_id (role assignment surface)
//
// Bearer auth via GustoAccessConnector.newRequest.

func gustoValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("gusto: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("gusto: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *GustoAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("gusto: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *GustoAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := gustoValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/v1/companies/%s/employees/%s/jobs/%s",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(cfg.CompanyID)),
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
		return fmt.Errorf("gusto: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("gusto: provision status %d: %s", status, string(body))
	}
}

func (c *GustoAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := gustoValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/v1/companies/%s/employees/%s/jobs/%s",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(cfg.CompanyID)),
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
		return fmt.Errorf("gusto: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("gusto: revoke status %d: %s", status, string(body))
	}
}

func (c *GustoAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("gusto: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/v1/companies/%s/employees/%s/jobs",
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
		return nil, fmt.Errorf("gusto: list jobs status %d: %s", status, string(body))
	}
	var jobs []struct {
		ID    interface{} `json:"id"`
		Title string      `json:"title"`
	}
	if err := json.Unmarshal(body, &jobs); err != nil {
		return nil, fmt.Errorf("gusto: decode jobs: %w", err)
	}
	out := make([]access.Entitlement, 0, len(jobs))
	for _, j := range jobs {
		id := strings.TrimSpace(fmt.Sprintf("%v", j.ID))
		if id == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: id,
			Role:               strings.TrimSpace(j.Title),
			Source:             "direct",
		})
	}
	return out, nil
}
