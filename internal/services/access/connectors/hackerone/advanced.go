package hackerone

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

// advanced-capability mapping for hackerone:
//
//   - ProvisionAccess  -> POST   /v1/organizations/{org_id}/members
//   - RevokeAccess     -> DELETE /v1/organizations/{org_id}/members/{user_id}
//   - ListEntitlements -> GET    /v1/organizations/{org_id}/members/{user_id}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> HackerOne member email/id
//   - grant.ResourceExternalID -> role slug (admin|program-manager|standard|...)
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func hackeroneValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("hackerone: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("hackerone: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *HackerOneAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("hackerone: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *HackerOneAccessConnector) membersURL(cfg Config) string {
	return c.baseURL() + "/v1/organizations/" + url.PathEscape(strings.TrimSpace(cfg.OrgID)) + "/members"
}

func (c *HackerOneAccessConnector) memberURL(cfg Config, userID string) string {
	return c.membersURL(cfg) + "/" + url.PathEscape(strings.TrimSpace(userID))
}

func (c *HackerOneAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *HackerOneAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := hackeroneValidateGrant(grant); err != nil {
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
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.membersURL(cfg), payload)
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
		return fmt.Errorf("hackerone: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("hackerone: provision status %d: %s", status, string(body))
	}
}

func (c *HackerOneAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := hackeroneValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, c.memberURL(cfg, grant.UserExternalID), nil)
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
		return fmt.Errorf("hackerone: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("hackerone: revoke status %d: %s", status, string(body))
	}
}

func (c *HackerOneAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("hackerone: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.memberURL(cfg, user), nil)
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
		return nil, fmt.Errorf("hackerone: list entitlements status %d: %s", status, string(body))
	}
	var m struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("hackerone: decode entitlements: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(m.Email), user) &&
		strings.TrimSpace(m.ID) != user {
		return nil, nil
	}
	role := strings.TrimSpace(m.Role)
	if role == "" {
		return []access.Entitlement{}, nil
	}
	return []access.Entitlement{{
		ResourceExternalID: role,
		Role:               role,
		Source:             "direct",
	}}, nil
}
