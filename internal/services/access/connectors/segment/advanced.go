package segment

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

// advanced-capability mapping for segment:
//
//   - ProvisionAccess  -> POST   /users
//                         body {email, permissions:[{role_name}]}
//   - RevokeAccess     -> DELETE /users/{user_id}
//   - ListEntitlements -> GET    /users/{user_id}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Segment user id (workspace member id)
//   - grant.ResourceExternalID -> role name (e.g. "Workspace Owner",
//                                 "Source Admin", "Workspace Member")
//
// Auth reuses the existing newRequest helper which sets
// "Accept: application/vnd.segment.v1+json" and the bearer token.
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func segmentValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("segment: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("segment: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *SegmentAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("segment: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *SegmentAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if len(body) > 0 {
		rdr = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.segment.v1+json")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *SegmentAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := segmentValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"email": strings.TrimSpace(grant.UserExternalID),
		"permissions": []map[string]string{
			{"role_name": strings.TrimSpace(grant.ResourceExternalID)},
		},
	})
	endpoint := c.baseURL() + "/users"
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, endpoint, payload)
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
		return fmt.Errorf("segment: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("segment: provision status %d: %s", status, string(body))
	}
}

func (c *SegmentAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := segmentValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := c.baseURL() + "/users/" + url.PathEscape(strings.TrimSpace(grant.UserExternalID))
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
		return fmt.Errorf("segment: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("segment: revoke status %d: %s", status, string(body))
	}
}

type segmentPermission struct {
	RoleName  string   `json:"role_name"`
	RoleID    string   `json:"role_id"`
	Resources []string `json:"resources"`
}

type segmentUserDetail struct {
	ID          string              `json:"id"`
	Email       string              `json:"email"`
	Permissions []segmentPermission `json:"permissions"`
}

type segmentUserDetailResponse struct {
	Data struct {
		User segmentUserDetail `json:"user"`
	} `json:"data"`
}

func (c *SegmentAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("segment: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	endpoint := c.baseURL() + "/users/" + url.PathEscape(user)
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
		return nil, fmt.Errorf("segment: list entitlements status %d: %s", status, string(body))
	}
	var resp segmentUserDetailResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("segment: decode user: %w", err)
	}
	out := make([]access.Entitlement, 0, len(resp.Data.User.Permissions))
	for _, p := range resp.Data.User.Permissions {
		role := strings.TrimSpace(p.RoleName)
		if role == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: role,
			Role:               role,
			Source:             "direct",
		})
	}
	return out, nil
}
