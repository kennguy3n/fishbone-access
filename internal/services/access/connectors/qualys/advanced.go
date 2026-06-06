package qualys

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// advanced-capability mapping for Qualys VMDR /api/2.0/fo/user/:
//
//   - ProvisionAccess  -> POST /api/2.0/fo/user/?action=add
//   - RevokeAccess     -> POST /api/2.0/fo/user/?action=delete&login=<login>
//   - ListEntitlements -> GET  /api/2.0/fo/user/?action=list&login=<login>
//
// Qualys VMDR speaks form-encoded request bodies and XML responses for the
// /fo/user/ endpoint. Idempotent on (UserExternalID, ResourceExternalID) per
// docs/architecture.md §2.

func qualysValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("qualys: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("qualys: grant.ResourceExternalID is required")
	}
	return nil
}

func qualysScopeString(g access.AccessGrant, key string) string {
	if g.Scope == nil {
		return ""
	}
	if v, ok := g.Scope[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// qualysProvisionFields resolves the first_name / last_name / email fields
// required by `/api/2.0/fo/user/?action=add`. Provisioners SHOULD set these
// via grant.Scope["first_name"] / ["last_name"] / ["email"]; the helper
// derives sensible fallbacks so the call never echoes UserExternalID into
// every identity field. For email specifically the fallback uses RFC 6761's
// reserved `.invalid` TLD when the login is not already an addr-spec, which
// guarantees the placeholder cannot route real mail.
func qualysProvisionFields(g access.AccessGrant) (firstName, lastName, email string) {
	login := strings.TrimSpace(g.UserExternalID)
	firstName = qualysScopeString(g, "first_name")
	if firstName == "" {
		firstName = "Provisioned"
	}
	lastName = qualysScopeString(g, "last_name")
	if lastName == "" {
		lastName = login
	}
	email = qualysScopeString(g, "email")
	if email == "" {
		if strings.Contains(login, "@") {
			email = login
		} else {
			email = login + "@user.invalid"
		}
	}
	return
}

func (c *QualysAccessConnector) userActionURL(cfg Config, q url.Values) string {
	return c.baseURL(cfg) + "/api/2.0/fo/user/?" + q.Encode()
}

func (c *QualysAccessConnector) newFormRequest(ctx context.Context, secrets Secrets, method, fullURL, body string) (*http.Request, error) {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/xml")
	req.Header.Set("X-Requested-With", "shieldnet360-access")
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	creds := strings.TrimSpace(secrets.Username) + ":" + strings.TrimSpace(secrets.Password)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *QualysAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("qualys: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *QualysAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := qualysValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	firstName, lastName, email := qualysProvisionFields(grant)
	form := url.Values{
		"user_login":    []string{strings.TrimSpace(grant.UserExternalID)},
		"user_role":     []string{strings.TrimSpace(grant.ResourceExternalID)},
		"first_name":    []string{firstName},
		"last_name":     []string{lastName},
		"email":         []string{email},
		"business_unit": []string{"Unassigned"},
		"send_email":    []string{"0"},
	}
	full := c.userActionURL(cfg, url.Values{"action": []string{"add"}})
	req, err := c.newFormRequest(ctx, secrets, http.MethodPost, full, form.Encode())
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
		return fmt.Errorf("qualys: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("qualys: provision status %d: %s", status, string(body))
	}
}

func (c *QualysAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := qualysValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	full := c.userActionURL(cfg, url.Values{
		"action": []string{"delete"},
		"login":  []string{strings.TrimSpace(grant.UserExternalID)},
	})
	req, err := c.newFormRequest(ctx, secrets, http.MethodPost, full, "")
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
		return fmt.Errorf("qualys: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("qualys: revoke status %d: %s", status, string(body))
	}
}

func (c *QualysAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	login := strings.TrimSpace(userExternalID)
	if login == "" {
		return nil, errors.New("qualys: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	full := c.userActionURL(cfg, url.Values{
		"action": []string{"list"},
		"login":  []string{login},
	})
	req, err := c.newFormRequest(ctx, secrets, http.MethodGet, full, "")
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
		return nil, fmt.Errorf("qualys: list entitlements status %d: %s", status, string(body))
	}
	var resp qualysUserList
	if err := xml.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("qualys: decode entitlements xml: %w", err)
	}
	for _, u := range resp.Response.UserList.Users {
		if !strings.EqualFold(strings.TrimSpace(u.UserLogin), login) &&
			strings.TrimSpace(u.UserID) != login {
			continue
		}
		role := strings.TrimSpace(u.UserRole)
		if role == "" {
			return []access.Entitlement{}, nil
		}
		return []access.Entitlement{{
			ResourceExternalID: role,
			Role:               role,
			Source:             "direct",
		}}, nil
	}
	return nil, nil
}
