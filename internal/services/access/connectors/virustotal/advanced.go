package virustotal

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

// advanced-capability mapping for virustotal:
//
//   - ProvisionAccess  -> POST   /api/v3/groups/{group_id}/relationships/users
//   - RevokeAccess     -> DELETE /api/v3/groups/{group_id}/relationships/users/{user_id}
//   - ListEntitlements -> GET    /api/v3/users/{user_id}/groups
//
// AccessGrant maps:
//   - grant.UserExternalID     -> VirusTotal user ID/email
//   - grant.ResourceExternalID -> group ID (e.g. premium-services-tenant slug)
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func vtValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("virustotal: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("virustotal: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *VirusTotalAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("virustotal: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *VirusTotalAccessConnector) groupMembersURL(groupID string) string {
	return c.baseURL() + "/api/v3/groups/" + url.PathEscape(strings.TrimSpace(groupID)) + "/relationships/users"
}

func (c *VirusTotalAccessConnector) groupMemberURL(groupID, userID string) string {
	return c.groupMembersURL(groupID) + "/" + url.PathEscape(strings.TrimSpace(userID))
}

func (c *VirusTotalAccessConnector) userGroupsURL(userID string) string {
	return c.baseURL() + "/api/v3/users/" + url.PathEscape(strings.TrimSpace(userID)) + "/groups"
}

func (c *VirusTotalAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("x-apikey", strings.TrimSpace(secrets.APIKey))
	return req, nil
}

func (c *VirusTotalAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := vtValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"data": []map[string]string{{
			"type": "user",
			"id":   strings.TrimSpace(grant.UserExternalID),
		}},
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost,
		c.groupMembersURL(grant.ResourceExternalID), payload)
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
		return fmt.Errorf("virustotal: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("virustotal: provision status %d: %s", status, string(body))
	}
}

func (c *VirusTotalAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := vtValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete,
		c.groupMemberURL(grant.ResourceExternalID, grant.UserExternalID), nil)
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
		return fmt.Errorf("virustotal: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("virustotal: revoke status %d: %s", status, string(body))
	}
}

func (c *VirusTotalAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("virustotal: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.userGroupsURL(user), nil)
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
		return nil, fmt.Errorf("virustotal: list entitlements status %d: %s", status, string(body))
	}
	var resp struct {
		Data []struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("virustotal: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0, len(resp.Data))
	for _, g := range resp.Data {
		id := strings.TrimSpace(g.ID)
		if id == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: id,
			Role:               "member",
			Source:             "direct",
		})
	}
	return out, nil
}
