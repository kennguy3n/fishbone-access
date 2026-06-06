package grafana

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

// advanced-capability mapping for Grafana:
//
//   - ProvisionAccess  -> POST   /api/org/users        body {loginOrEmail, role}
//   - RevokeAccess     -> DELETE /api/org/users/{user_id}
//   - ListEntitlements -> GET    /api/org/users
//                         (filtered to {grant.UserExternalID})
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Grafana `loginOrEmail` (filtered on GET)
//   - grant.ResourceExternalID -> role name (Viewer / Editor / Admin)
//                                 ("" defaults to "Viewer")
//   - For DELETE the connector looks up the numeric user_id via GET first.
//
// Grafana returns 409 / 400 ("user is already member of this organization")
// on duplicate add — access.IsIdempotentProvisionStatus normalises that
// to idempotent success. 404 on DELETE / GET is treated as success.

const grafanaDefaultRole = "Viewer"

func grafanaValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("grafana: grant.UserExternalID is required")
	}
	return nil
}

func grafanaRole(g access.AccessGrant) string {
	if r := strings.TrimSpace(g.Role); r != "" {
		return r
	}
	if r := strings.TrimSpace(g.ResourceExternalID); r != "" {
		return r
	}
	return grafanaDefaultRole
}

func (c *GrafanaAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	if t := strings.TrimSpace(secrets.Token); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	} else {
		creds := strings.TrimSpace(secrets.Username) + ":" + strings.TrimSpace(secrets.Password)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	}
	return req, nil
}

func (c *GrafanaAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("grafana: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

// ProvisionAccess adds the user to the current org.
func (c *GrafanaAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := grafanaValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{
		"loginOrEmail": strings.TrimSpace(grant.UserExternalID),
		"role":         grafanaRole(grant),
	})
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPost,
		c.baseURL(cfg)+"/api/org/users", payload)
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
		return fmt.Errorf("grafana: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("grafana: provision status %d: %s", status, string(body))
	}
}

// RevokeAccess removes the user from the current org.
func (c *GrafanaAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := grafanaValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	userID, err := c.findGrafanaUserID(ctx, cfg, secrets, grant.UserExternalID)
	if err != nil {
		return err
	}
	if userID == 0 {
		return nil
	}
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodDelete,
		fmt.Sprintf("%s/api/org/users/%d", c.baseURL(cfg), userID), nil)
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
		return fmt.Errorf("grafana: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("grafana: revoke status %d: %s", status, string(body))
	}
}

// ListEntitlements returns the org role currently bound to the user.
func (c *GrafanaAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("grafana: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	users, err := c.listGrafanaOrgUsers(ctx, cfg, secrets)
	if err != nil {
		return nil, err
	}
	for i := range users {
		if strings.EqualFold(strings.TrimSpace(users[i].Login), user) ||
			strings.EqualFold(strings.TrimSpace(users[i].Email), user) {
			role := strings.TrimSpace(users[i].Role)
			if role == "" {
				role = grafanaDefaultRole
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

func (c *GrafanaAccessConnector) findGrafanaUserID(ctx context.Context, cfg Config, secrets Secrets, loginOrEmail string) (int64, error) {
	users, err := c.listGrafanaOrgUsers(ctx, cfg, secrets)
	if err != nil {
		return 0, err
	}
	want := strings.TrimSpace(loginOrEmail)
	for i := range users {
		if strings.EqualFold(strings.TrimSpace(users[i].Login), want) ||
			strings.EqualFold(strings.TrimSpace(users[i].Email), want) {
			return users[i].UserID, nil
		}
	}
	return 0, nil
}

func (c *GrafanaAccessConnector) listGrafanaOrgUsers(ctx context.Context, cfg Config, secrets Secrets) ([]grafanaOrgUser, error) {
	req, err := c.newRequest(ctx, secrets, http.MethodGet,
		c.baseURL(cfg)+"/api/org/users?"+url.Values{}.Encode())
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
		return nil, fmt.Errorf("grafana: list org users status %d: %s", status, string(body))
	}
	var out []grafanaOrgUser
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("grafana: decode org users: %w", err)
	}
	return out, nil
}

type grafanaOrgUser struct {
	UserID int64  `json:"userId"`
	Login  string `json:"login"`
	Email  string `json:"email"`
	Role   string `json:"role"`
}
