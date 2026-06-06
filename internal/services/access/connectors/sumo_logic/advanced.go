package sumo_logic

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

// advanced-capability mapping for Sumo Logic:
//
//   - ProvisionAccess  -> PUT    /api/v1/roles/{roleId}/users/{userId}
//   - RevokeAccess     -> DELETE /api/v1/roles/{roleId}/users/{userId}
//   - ListEntitlements -> GET    /api/v1/users/{userId}  (roleIds[])
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Sumo Logic user id
//   - grant.ResourceExternalID -> Sumo Logic role id
//
// HTTP Basic accessId:accessKey auth via sumo_logic.newRequest.

func sumoValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("sumo_logic: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("sumo_logic: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *SumoLogicAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("X-Sumo-Client", "shieldnet360-access")
	creds := strings.TrimSpace(secrets.AccessID) + ":" + strings.TrimSpace(secrets.AccessKey)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *SumoLogicAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("sumo_logic: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *SumoLogicAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := sumoValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/api/v1/roles/%s/users/%s",
		c.baseURL(cfg),
		url.PathEscape(strings.TrimSpace(grant.ResourceExternalID)),
		url.PathEscape(strings.TrimSpace(grant.UserExternalID)))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPut, endpoint, nil)
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
		return fmt.Errorf("sumo_logic: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("sumo_logic: provision status %d: %s", status, string(body))
	}
}

func (c *SumoLogicAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := sumoValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/api/v1/roles/%s/users/%s",
		c.baseURL(cfg),
		url.PathEscape(strings.TrimSpace(grant.ResourceExternalID)),
		url.PathEscape(strings.TrimSpace(grant.UserExternalID)))
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
		return fmt.Errorf("sumo_logic: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("sumo_logic: revoke status %d: %s", status, string(body))
	}
}

func (c *SumoLogicAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("sumo_logic: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/api/v1/users/%s",
		c.baseURL(cfg), url.PathEscape(user))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, endpoint)
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
		return nil, fmt.Errorf("sumo_logic: list user status %d: %s", status, string(body))
	}
	var resp struct {
		ID      string   `json:"id"`
		RoleIDs []string `json:"roleIds"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("sumo_logic: decode user: %w", err)
	}
	out := make([]access.Entitlement, 0, len(resp.RoleIDs))
	for _, id := range resp.RoleIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: id,
			Role:               id,
			Source:             "direct",
		})
	}
	return out, nil
}
