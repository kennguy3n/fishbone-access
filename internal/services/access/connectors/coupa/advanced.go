package coupa

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

// advanced-capability mapping for coupa:
//
//   - ProvisionAccess  -> POST /api/users
//   - RevokeAccess     -> PUT  /api/users/{login}/deactivate
//   - ListEntitlements -> GET  /api/users?login={login}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Coupa login (or numeric user id)
//   - grant.ResourceExternalID -> role name (e.g. "Buyer", "Approver")
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func coupaValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("coupa: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("coupa: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *CoupaAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("coupa: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *CoupaAccessConnector) usersURL(cfg Config) string {
	return c.baseURL(cfg) + "/api/users"
}

func (c *CoupaAccessConnector) userURL(cfg Config, login string) string {
	return c.usersURL(cfg) + "/" + url.PathEscape(strings.TrimSpace(login))
}

func (c *CoupaAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("X-COUPA-API-KEY", strings.TrimSpace(secrets.APIKey))
	return req, nil
}

func (c *CoupaAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := coupaValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"login":  strings.TrimSpace(grant.UserExternalID),
		"active": true,
		"roles":  []map[string]string{{"name": strings.TrimSpace(grant.ResourceExternalID)}},
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.usersURL(cfg), payload)
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
		return fmt.Errorf("coupa: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("coupa: provision status %d: %s", status, string(body))
	}
}

func (c *CoupaAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := coupaValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPut,
		c.userURL(cfg, grant.UserExternalID)+"/deactivate",
		[]byte(`{}`))
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
		return fmt.Errorf("coupa: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("coupa: revoke status %d: %s", status, string(body))
	}
}

func (c *CoupaAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("coupa: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	q := url.Values{"login": []string{user}}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet,
		c.usersURL(cfg)+"?"+q.Encode(), nil)
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
		return nil, fmt.Errorf("coupa: list entitlements status %d: %s", status, string(body))
	}
	type coupaRole struct {
		Name string `json:"name"`
		ID   int    `json:"id"`
	}
	type coupaUser struct {
		Login  string      `json:"login"`
		Active bool        `json:"active"`
		Roles  []coupaRole `json:"roles"`
	}
	var users []coupaUser
	if err := json.Unmarshal(body, &users); err != nil {
		return nil, fmt.Errorf("coupa: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0)
	for _, u := range users {
		if !strings.EqualFold(strings.TrimSpace(u.Login), user) {
			continue
		}
		if !u.Active {
			continue
		}
		for _, r := range u.Roles {
			role := strings.TrimSpace(r.Name)
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
