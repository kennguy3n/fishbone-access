package mixpanel

import (
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

// advanced-capability mapping for mixpanel:
//
//   - ProvisionAccess  -> POST   /api/app/organizations/{org_id}/members
//                         body {email, role}
//   - RevokeAccess     -> DELETE /api/app/organizations/{org_id}/members?email=...
//                         (Mixpanel keys members by id; we resolve via
//                          the email query parameter to keep callers
//                          honest about the AccessGrant key)
//   - ListEntitlements -> GET    /api/app/organizations/{org_id}/members
//
// AccessGrant maps:
//   - grant.UserExternalID     -> member email address
//   - grant.ResourceExternalID -> Mixpanel role (e.g. "owner", "admin",
//                                 "member", "billing-admin")
//
// Auth uses Basic auth with the service-account user + secret, reusing
// the existing newRequest helper. Idempotent on
// (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func mixpanelValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("mixpanel: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("mixpanel: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *MixpanelAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("mixpanel: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *MixpanelAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	creds := strings.TrimSpace(secrets.ServiceAccountUser) + ":" + strings.TrimSpace(secrets.ServiceAccountSecret)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *MixpanelAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := mixpanelValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{
		"email": strings.TrimSpace(grant.UserExternalID),
		"role":  strings.TrimSpace(grant.ResourceExternalID),
	})
	endpoint := c.baseURL() + c.buildPath(cfg)
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, endpoint, payload)
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
		return fmt.Errorf("mixpanel: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("mixpanel: provision status %d: %s", status, string(body))
	}
}

func (c *MixpanelAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := mixpanelValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	q := url.Values{"email": []string{strings.TrimSpace(grant.UserExternalID)}}
	endpoint := c.baseURL() + c.buildPath(cfg) + "?" + q.Encode()
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
		return fmt.Errorf("mixpanel: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("mixpanel: revoke status %d: %s", status, string(body))
	}
}

func (c *MixpanelAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("mixpanel: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	endpoint := c.baseURL() + c.buildPath(cfg)
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, endpoint, nil)
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
		return nil, fmt.Errorf("mixpanel: list entitlements status %d: %s", status, string(body))
	}
	var resp mxListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("mixpanel: decode members: %w", err)
	}
	out := make([]access.Entitlement, 0, len(resp.Members))
	for _, m := range resp.Members {
		if !strings.EqualFold(strings.TrimSpace(m.Email), user) {
			continue
		}
		role := strings.TrimSpace(m.Role)
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
