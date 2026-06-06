package splunk

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

// advanced-capability mapping for Splunk Cloud:
//
//   - ProvisionAccess  -> POST   /services/authentication/users
//                                form name=USER&password=…&roles=ROLE
//   - RevokeAccess     -> DELETE /services/authentication/users/{name}
//   - ListEntitlements -> GET    /services/authentication/users/{name}?output_mode=json
//
// AccessGrant maps:
//   - grant.UserExternalID     -> username (`name`)
//   - grant.ResourceExternalID -> role name (or "user" if blank)
//
// Splunk returns 409 / 400 ("already exists") for duplicate users —
// access.IsIdempotentProvisionStatus normalises that to idempotent
// success. 404 on DELETE / GET is treated as success per docs/architecture.md §2.

const splunkDefaultRole = "user"

func splunkValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("splunk: grant.UserExternalID is required")
	}
	return nil
}

func splunkRole(g access.AccessGrant) string {
	if r := strings.TrimSpace(g.Role); r != "" {
		return r
	}
	if r := strings.TrimSpace(g.ResourceExternalID); r != "" {
		return r
	}
	return splunkDefaultRole
}

func splunkPasswordFromScope(g access.AccessGrant) string {
	if g.Scope == nil {
		return ""
	}
	if v, ok := g.Scope["password"].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func (c *SplunkAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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

func (c *SplunkAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("splunk: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

// ProvisionAccess creates the user (idempotent on 409 / 400 "already exists").
func (c *SplunkAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := splunkValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	form := url.Values{}
	form.Set("name", strings.TrimSpace(grant.UserExternalID))
	form.Set("roles", splunkRole(grant))
	form.Set("output_mode", "json")
	if pw := splunkPasswordFromScope(grant); pw != "" {
		form.Set("password", pw)
	}
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPost,
		c.baseURL(cfg)+"/services/authentication/users", []byte(form.Encode()))
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
		return fmt.Errorf("splunk: provision transient status %d: %s", status, formatErrorBody(body))
	default:
		return fmt.Errorf("splunk: provision status %d: %s", status, formatErrorBody(body))
	}
}

// RevokeAccess deletes the user. 404 is treated as idempotent success.
func (c *SplunkAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := splunkValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	name := url.PathEscape(strings.TrimSpace(grant.UserExternalID))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodDelete,
		c.baseURL(cfg)+"/services/authentication/users/"+name+"?output_mode=json", nil)
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
		return fmt.Errorf("splunk: revoke transient status %d: %s", status, formatErrorBody(body))
	default:
		return fmt.Errorf("splunk: revoke status %d: %s", status, formatErrorBody(body))
	}
}

// ListEntitlements returns the roles currently bound to the user.
func (c *SplunkAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("splunk: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet,
		c.baseURL(cfg)+"/services/authentication/users/"+url.PathEscape(user)+"?output_mode=json")
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
		return nil, fmt.Errorf("splunk: list entitlements status %d: %s", status, formatErrorBody(body))
	}
	var resp splunkUsersResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("splunk: decode user: %w", err)
	}
	var out []access.Entitlement
	for i := range resp.Entry {
		for _, role := range resp.Entry[i].Content.Roles {
			role = strings.TrimSpace(role)
			if role == "" {
				continue
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

type splunkUsersResponse struct {
	Entry []struct {
		Name    string `json:"name"`
		Content struct {
			Roles []string `json:"roles"`
			Email string   `json:"email"`
		} `json:"content"`
	} `json:"entry"`
}
