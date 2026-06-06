package sonarcloud

import (
	"bytes"
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

// advanced-capability mapping for SonarCloud:
//
//   - ProvisionAccess  -> POST   /api/organizations/add_member?organization=X&login=Y
//   - RevokeAccess     -> POST   /api/organizations/remove_member?organization=X&login=Y
//   - ListEntitlements -> GET    /api/organizations/search_members?organization=X&q=Y
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Sonar `login` (e.g. github account login)
//   - grant.ResourceExternalID -> always the configured organization key
//     (callers can still set it explicitly to override on multi-org tokens)
//
// SonarCloud accepts the same add_member call repeatedly without
// changing state (returns 200 / 204 each time), so ProvisionAccess is
// naturally idempotent. RevokeAccess treats 404 + "not a member" /
// "user not found" body matches as idempotent success per docs/architecture.md §2.

func sonarCloudValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("sonarcloud: grant.UserExternalID is required")
	}
	return nil
}

func (c *SonarCloudAccessConnector) organizationKey(cfg Config, g access.AccessGrant) string {
	if r := strings.TrimSpace(g.ResourceExternalID); r != "" {
		return r
	}
	return strings.TrimSpace(cfg.Organization)
}

func (c *SonarCloudAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *SonarCloudAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("sonarcloud: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

// ProvisionAccess adds the user to the organization.
func (c *SonarCloudAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := sonarCloudValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	org := c.organizationKey(cfg, grant)
	if org == "" {
		return errors.New("sonarcloud: organization is required")
	}
	form := url.Values{}
	form.Set("organization", org)
	form.Set("login", strings.TrimSpace(grant.UserExternalID))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPost,
		c.baseURL()+"/api/organizations/add_member", []byte(form.Encode()))
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
		return fmt.Errorf("sonarcloud: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("sonarcloud: provision status %d: %s", status, string(body))
	}
}

// RevokeAccess removes the user from the organization.
func (c *SonarCloudAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := sonarCloudValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	org := c.organizationKey(cfg, grant)
	if org == "" {
		return errors.New("sonarcloud: organization is required")
	}
	form := url.Values{}
	form.Set("organization", org)
	form.Set("login", strings.TrimSpace(grant.UserExternalID))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPost,
		c.baseURL()+"/api/organizations/remove_member", []byte(form.Encode()))
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
		return fmt.Errorf("sonarcloud: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("sonarcloud: revoke status %d: %s", status, string(body))
	}
}

// ListEntitlements returns a single entitlement when the user is a
// member of the configured organization.
func (c *SonarCloudAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("sonarcloud: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("organization", strings.TrimSpace(cfg.Organization))
	q.Set("q", user)
	q.Set("p", "1")
	q.Set("ps", "100")
	req, err := c.newRequest(ctx, secrets, http.MethodGet,
		c.baseURL()+"/api/organizations/search_members?"+q.Encode())
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
		return nil, fmt.Errorf("sonarcloud: list entitlements status %d: %s", status, string(body))
	}
	var resp sonarCloudMembersResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("sonarcloud: decode members: %w", err)
	}
	for i := range resp.Users {
		if strings.EqualFold(strings.TrimSpace(resp.Users[i].Login), user) {
			return []access.Entitlement{{
				ResourceExternalID: strings.TrimSpace(cfg.Organization),
				Role:               "member",
				Source:             "direct",
			}}, nil
		}
	}
	return nil, nil
}

type sonarCloudMembersResponse struct {
	Paging struct {
		PageIndex int `json:"pageIndex"`
		PageSize  int `json:"pageSize"`
		Total     int `json:"total"`
	} `json:"paging"`
	Users []struct {
		Login string `json:"login"`
		Name  string `json:"name"`
	} `json:"users"`
}
