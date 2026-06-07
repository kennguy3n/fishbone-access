package sophos_xg

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

// advanced-capability mapping for Sophos XG /api/admins:
//
//   - ProvisionAccess  -> POST   /api/admins             (provision firewall admin with profile)
//   - RevokeAccess     -> DELETE /api/admins/{username}  (remove admin)
//   - ListEntitlements -> GET    /api/admins/{username}  (current profile)
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Sophos XG admin username
//   - grant.ResourceExternalID -> admin profile slug ("administrator", "audit_admin", "crypto_admin")
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func sophosXGValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("sophos_xg: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("sophos_xg: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *SophosXGAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("sophos_xg: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *SophosXGAccessConnector) adminsURL() string {
	return c.baseURL() + "/api/admins"
}

func (c *SophosXGAccessConnector) adminURL(username string) string {
	return c.adminsURL() + "/" + url.PathEscape(strings.TrimSpace(username))
}

func (c *SophosXGAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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

func (c *SophosXGAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := sophosXGValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"username": strings.TrimSpace(grant.UserExternalID),
		"profile":  strings.TrimSpace(grant.ResourceExternalID),
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.adminsURL(), payload)
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
		return fmt.Errorf("sophos_xg: provision transient status %d: %s", status, formatErrorBody(body))
	default:
		return fmt.Errorf("sophos_xg: provision status %d: %s", status, formatErrorBody(body))
	}
}

func (c *SophosXGAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := sophosXGValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, c.adminURL(grant.UserExternalID), nil)
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
		return fmt.Errorf("sophos_xg: revoke transient status %d: %s", status, formatErrorBody(body))
	default:
		return fmt.Errorf("sophos_xg: revoke status %d: %s", status, formatErrorBody(body))
	}
}

func (c *SophosXGAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("sophos_xg: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.adminURL(user), nil)
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
		return nil, fmt.Errorf("sophos_xg: list entitlements status %d: %s", status, formatErrorBody(body))
	}
	var resp struct {
		Admin struct {
			Username string `json:"username"`
			Profile  string `json:"profile"`
		} `json:"admin"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("sophos_xg: decode entitlements: %w", err)
	}
	profile := strings.TrimSpace(resp.Admin.Profile)
	if profile == "" {
		return []access.Entitlement{}, nil
	}
	return []access.Entitlement{{
		ResourceExternalID: profile,
		Role:               profile,
		Source:             "direct",
	}}, nil
}
