package expensify

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

// advanced-capability mapping for expensify:
//
//   - ProvisionAccess  -> POST /Integration-Server/ExpensifyIntegrations
//     with inputSettings.type="employeesCreate", body carrying the
//     {policyID, employees:[{email, role}]} envelope.
//   - RevokeAccess     -> POST /Integration-Server/ExpensifyIntegrations
//     with inputSettings.type="employeesRemove" + {policyID, employees:[{email}]}.
//   - ListEntitlements -> POST /Integration-Server/ExpensifyIntegrations
//     with the existing "policyList" / "get" envelope.
//
// AccessGrant maps:
//   - grant.UserExternalID     -> employee email
//   - grant.ResourceExternalID -> policy role (admin|auditor|user|...)
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2:
// Expensify returns 200 with an embedded responseCode for "already a
// member"/"not a member"; we map those bodies plus the standard
// 4xx/409 status codes via access.IsIdempotent* helpers.

func expensifyValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("expensify: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("expensify: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *ExpensifyAccessConnector) doJob(ctx context.Context, jobBody string) (int, []byte, error) {
	form := url.Values{"requestJobDescription": []string{jobBody}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL()+"/Integration-Server/ExpensifyIntegrations",
		strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("expensify: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *ExpensifyAccessConnector) buildAccessJob(action, policyID, email, role string, secrets Secrets) (string, error) {
	emp := map[string]string{"email": strings.TrimSpace(email)}
	if strings.TrimSpace(role) != "" {
		emp["role"] = strings.TrimSpace(role)
	}
	payload := map[string]interface{}{
		"type": "create",
		"credentials": map[string]string{
			"partnerUserID":     strings.TrimSpace(secrets.PartnerUserID),
			"partnerUserSecret": strings.TrimSpace(secrets.PartnerUserSecret),
		},
		"inputSettings": map[string]interface{}{
			"type":      action,
			"policyID":  strings.TrimSpace(policyID),
			"employees": []map[string]string{emp},
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (c *ExpensifyAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := expensifyValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body, err := c.buildAccessJob("employeesCreate", cfg.PolicyID, grant.UserExternalID, grant.ResourceExternalID, secrets)
	if err != nil {
		return err
	}
	status, respBody, err := c.doJob(ctx, body)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		if expensifyBodyIndicatesError(respBody) {
			if expensifyBodyIsAlreadyMember(respBody) {
				return nil
			}
			return fmt.Errorf("expensify: provision response: %s", string(respBody))
		}
		return nil
	case access.IsIdempotentProvisionStatus(status, respBody):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("expensify: provision transient status %d: %s", status, string(respBody))
	default:
		return fmt.Errorf("expensify: provision status %d: %s", status, string(respBody))
	}
}

func (c *ExpensifyAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := expensifyValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body, err := c.buildAccessJob("employeesRemove", cfg.PolicyID, grant.UserExternalID, "", secrets)
	if err != nil {
		return err
	}
	status, respBody, err := c.doJob(ctx, body)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		if expensifyBodyIndicatesError(respBody) {
			if expensifyBodyIsNotMember(respBody) {
				return nil
			}
			return fmt.Errorf("expensify: revoke response: %s", string(respBody))
		}
		return nil
	case access.IsIdempotentRevokeStatus(status, respBody):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("expensify: revoke transient status %d: %s", status, string(respBody))
	default:
		return fmt.Errorf("expensify: revoke status %d: %s", status, string(respBody))
	}
}

func (c *ExpensifyAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("expensify: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	jobBody, err := c.buildRequestJSON(cfg, secrets)
	if err != nil {
		return nil, err
	}
	status, body, err := c.doJob(ctx, jobBody)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("expensify: list entitlements status %d: %s", status, string(body))
	}
	var resp expResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("expensify: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0)
	for _, p := range resp.PolicyList {
		for _, e := range p.Employees {
			if !strings.EqualFold(e.Email, user) {
				continue
			}
			role := strings.TrimSpace(e.Role)
			if role == "" {
				role = "user"
			}
			out = append(out, access.Entitlement{
				ResourceExternalID: role,
				Role:               role,
				Source:             "direct",
			})
		}
	}
	return out, nil
}

func expensifyBodyIndicatesError(body []byte) bool {
	var envelope struct {
		ResponseCode    int    `json:"responseCode"`
		ResponseMessage string `json:"responseMessage"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return false
	}
	if envelope.ResponseCode != 0 && envelope.ResponseCode != 200 {
		return true
	}
	return strings.TrimSpace(envelope.ResponseMessage) != "" && envelope.ResponseCode == 0
}

func expensifyBodyIsAlreadyMember(body []byte) bool {
	return access.IsIdempotentMessage(string(body),
		[]string{"already", "duplicate", "exists", "is a member"})
}

func expensifyBodyIsNotMember(body []byte) bool {
	return access.IsIdempotentMessage(string(body),
		[]string{"not a member", "not found", "does not exist", "no such"})
}
