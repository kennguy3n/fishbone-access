package insightly

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

// advanced-capability mapping for insightly:
//
//   - ProvisionAccess  -> POST   /v3.1/Permissions
//   - RevokeAccess     -> DELETE /v3.1/Permissions/{id}
//   - ListEntitlements -> GET    /v3.1/Permissions?user_id={userId}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Insightly user id
//   - grant.ResourceExternalID -> permission id (or "<permission_name>"
//     for fresh provision; the API echoes back the assigned id)
//
// HTTP Basic auth with api_key:<blank> reuses the existing
// connector.newRequest helper. Idempotent on (UserExternalID,
// ResourceExternalID).

func insightlyValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("insightly: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("insightly: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *InsightlyAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("insightly: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *InsightlyAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	creds := strings.TrimSpace(secrets.APIKey) + ":"
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *InsightlyAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := insightlyValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"USER_ID":         strings.TrimSpace(grant.UserExternalID),
		"PERMISSION_NAME": strings.TrimSpace(grant.ResourceExternalID),
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.baseURL(cfg)+"/v3.1/Permissions", payload)
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
		return fmt.Errorf("insightly: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("insightly: provision status %d: %s", status, string(body))
	}
}

func (c *InsightlyAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := insightlyValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := c.baseURL(cfg) + "/v3.1/Permissions/" + url.PathEscape(strings.TrimSpace(grant.ResourceExternalID))
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
		return fmt.Errorf("insightly: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("insightly: revoke status %d: %s", status, string(body))
	}
}

func (c *InsightlyAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("insightly: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("user_id", user)
	endpoint := c.baseURL(cfg) + "/v3.1/Permissions?" + q.Encode()
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
		return nil, fmt.Errorf("insightly: list entitlements status %d: %s", status, string(body))
	}
	var permissions []struct {
		PermissionID   interface{} `json:"PERMISSION_ID"`
		PermissionName string      `json:"PERMISSION_NAME"`
		UserID         interface{} `json:"USER_ID"`
	}
	if err := json.Unmarshal(body, &permissions); err != nil {
		return nil, fmt.Errorf("insightly: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0, len(permissions))
	for _, p := range permissions {
		id := strings.TrimSpace(fmt.Sprintf("%v", p.PermissionID))
		if id == "" || id == "<nil>" {
			id = strings.TrimSpace(p.PermissionName)
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: id,
			Role:               strings.TrimSpace(p.PermissionName),
			Source:             "direct",
		})
	}
	return out, nil
}
