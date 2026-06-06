package paloalto

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

// advanced-capability mapping for paloalto (Prisma Cloud):
//
//   - ProvisionAccess  -> POST   /v2/user        (create or update user)
//   - RevokeAccess     -> DELETE /v2/user/{email}
//   - ListEntitlements -> GET    /v2/user/{email}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Prisma Cloud user email
//   - grant.ResourceExternalID -> role slug ("System Admin","Account Group Admin","Account Group Read Only",...)
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func paloaltoValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("paloalto: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("paloalto: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *PaloAltoAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("paloalto: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *PaloAltoAccessConnector) usersURL() string {
	return c.baseURL() + "/v2/user"
}

func (c *PaloAltoAccessConnector) userURL(email string) string {
	return c.usersURL() + "/" + url.PathEscape(strings.TrimSpace(email))
}

func (c *PaloAltoAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("x-redlock-auth", strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *PaloAltoAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := paloaltoValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"email":   strings.TrimSpace(grant.UserExternalID),
		"roleIds": []string{strings.TrimSpace(grant.ResourceExternalID)},
		"enabled": true,
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.usersURL(), payload)
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
		return fmt.Errorf("paloalto: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("paloalto: provision status %d: %s", status, string(body))
	}
}

func (c *PaloAltoAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := paloaltoValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, c.userURL(grant.UserExternalID), nil)
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
		return fmt.Errorf("paloalto: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("paloalto: revoke status %d: %s", status, string(body))
	}
}

func (c *PaloAltoAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("paloalto: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.userURL(user), nil)
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
		return nil, fmt.Errorf("paloalto: list entitlements status %d: %s", status, string(body))
	}
	var m struct {
		Email   string   `json:"email"`
		RoleIDs []string `json:"roleIds"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("paloalto: decode entitlements: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(m.Email), user) {
		return nil, nil
	}
	out := make([]access.Entitlement, 0, len(m.RoleIDs))
	for _, r := range m.RoleIDs {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: r,
			Role:               r,
			Source:             "direct",
		})
	}
	return out, nil
}
