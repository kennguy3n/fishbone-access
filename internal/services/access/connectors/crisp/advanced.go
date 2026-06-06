package crisp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// advanced-capability mapping for Crisp:
//
//   - ProvisionAccess  -> POST   /v1/website/{website_id}/operators
//                         body {email, role}
//   - RevokeAccess     -> DELETE /v1/website/{website_id}/operators/{user_id}
//                         (user_id looked up via /operators/list)
//   - ListEntitlements -> GET    /v1/website/{website_id}/operators/list
//                         (filtered to {grant.UserExternalID})
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Crisp operator email (preferred) or user_id
//   - grant.ResourceExternalID -> Crisp role (member / admin / owner; defaults to "member")
//
// HTTP Basic identifier:key auth via crisp.newRequest. Idempotency
// follows the standard access helpers — 409 / 400-with-"already" become
// success for provision, 404 / "not a member" become success for revoke.

const crispDefaultRole = "member"

func crispValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("crisp: grant.UserExternalID is required")
	}
	return nil
}

func crispRole(g access.AccessGrant) string {
	if r := strings.TrimSpace(g.Role); r != "" {
		return r
	}
	if r := strings.TrimSpace(g.ResourceExternalID); r != "" {
		return r
	}
	return crispDefaultRole
}

func (c *CrispAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Crisp-Tier", "plugin")
	creds := strings.TrimSpace(secrets.Identifier) + ":" + strings.TrimSpace(secrets.Key)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *CrispAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("crisp: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *CrispAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := crispValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{
		"email": strings.TrimSpace(grant.UserExternalID),
		"role":  crispRole(grant),
	})
	endpoint := fmt.Sprintf("%s/v1/website/%s/operators", c.baseURL(),
		url.PathEscape(strings.TrimSpace(cfg.WebsiteID)))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPost, endpoint, payload)
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
		return fmt.Errorf("crisp: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("crisp: provision status %d: %s", status, string(body))
	}
}

func (c *CrispAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := crispValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	userID, err := c.findCrispUserID(ctx, cfg, secrets, grant.UserExternalID)
	if err != nil {
		return err
	}
	if userID == "" {
		return nil
	}
	endpoint := fmt.Sprintf("%s/v1/website/%s/operators/%s", c.baseURL(),
		url.PathEscape(strings.TrimSpace(cfg.WebsiteID)),
		url.PathEscape(userID))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodDelete, endpoint, nil)
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
		return fmt.Errorf("crisp: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("crisp: revoke status %d: %s", status, string(body))
	}
}

func (c *CrispAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("crisp: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	ops, err := c.listCrispOperators(ctx, cfg, secrets)
	if err != nil {
		return nil, err
	}
	for i := range ops {
		if strings.EqualFold(strings.TrimSpace(ops[i].Details.Email), user) ||
			strings.EqualFold(strings.TrimSpace(ops[i].Details.UserID), user) {
			role := strings.TrimSpace(ops[i].Details.Role)
			if role == "" {
				role = crispDefaultRole
			}
			return []access.Entitlement{{
				ResourceExternalID: role,
				Role:               role,
				Source:             "direct",
			}}, nil
		}
	}
	return nil, nil
}

func (c *CrispAccessConnector) findCrispUserID(ctx context.Context, cfg Config, secrets Secrets, loginOrEmail string) (string, error) {
	ops, err := c.listCrispOperators(ctx, cfg, secrets)
	if err != nil {
		return "", err
	}
	want := strings.TrimSpace(loginOrEmail)
	for i := range ops {
		if strings.EqualFold(strings.TrimSpace(ops[i].Details.Email), want) ||
			strings.EqualFold(strings.TrimSpace(ops[i].Details.UserID), want) {
			return strings.TrimSpace(ops[i].Details.UserID), nil
		}
	}
	return "", nil
}

func (c *CrispAccessConnector) listCrispOperators(ctx context.Context, cfg Config, secrets Secrets) ([]crispOperator, error) {
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.operatorsURL(cfg))
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
		return nil, fmt.Errorf("crisp: list operators status %d: %s", status, string(body))
	}
	var resp crispListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("crisp: decode operators: %w", err)
	}
	return resp.Data, nil
}
