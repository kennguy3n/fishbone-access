package wrike

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

// advanced-capability mapping for Wrike:
//
//   - ProvisionAccess  -> PUT /api/v4/groups/{group_id}
//                         body addMembers=[user_id]
//   - RevokeAccess     -> PUT /api/v4/groups/{group_id}
//                         body removeMembers=[user_id]
//   - ListEntitlements -> GET /api/v4/groups/{group_id}
//                         (memberIds includes user)
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Wrike contact id (user)
//   - grant.ResourceExternalID -> Wrike group id
//
// Bearer auth via WrikeAccessConnector.newRequest.

func wrikeValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("wrike: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("wrike: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *WrikeAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *WrikeAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("wrike: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *WrikeAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := wrikeValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if c.userAlreadyInGroup(ctx, cfg, secrets, grant.ResourceExternalID, grant.UserExternalID) {
		return nil
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"addMembers": []string{strings.TrimSpace(grant.UserExternalID)},
	})
	endpoint := fmt.Sprintf("%s/api/v4/groups/%s", c.baseURL(cfg), url.PathEscape(strings.TrimSpace(grant.ResourceExternalID)))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPut, endpoint, payload)
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
		return fmt.Errorf("wrike: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("wrike: provision status %d: %s", status, string(body))
	}
}

func (c *WrikeAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := wrikeValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	// No pre-check here: a transient /groups/{id} fetch failure must NOT be
	// interpreted as "user not in group" — that would silently no-op the
	// revoke while the user retains access. We issue the PUT removeMembers
	// directly and let the idempotency-status handler absorb the response
	// when the user was never a member (Wrike returns 200 OK with the group
	// unchanged) or when the group itself is gone (404).
	payload, _ := json.Marshal(map[string]interface{}{
		"removeMembers": []string{strings.TrimSpace(grant.UserExternalID)},
	})
	endpoint := fmt.Sprintf("%s/api/v4/groups/%s", c.baseURL(cfg), url.PathEscape(strings.TrimSpace(grant.ResourceExternalID)))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPut, endpoint, payload)
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
		return fmt.Errorf("wrike: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("wrike: revoke status %d: %s", status, string(body))
	}
}

func (c *WrikeAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("wrike: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	groupID := wrikeOptionalGroupID(configRaw)
	if groupID == "" {
		return nil, errors.New("wrike: group_id is required in config for ListEntitlements")
	}
	group, err := c.fetchWrikeGroup(ctx, cfg, secrets, groupID)
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}
	for _, mid := range group.MemberIDs {
		if strings.EqualFold(strings.TrimSpace(mid), user) {
			return []access.Entitlement{{
				ResourceExternalID: groupID,
				Role:               "member",
				Source:             "direct",
			}}, nil
		}
	}
	return nil, nil
}

type wrikeGroup struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	MemberIDs []string `json:"memberIds"`
}

func (c *WrikeAccessConnector) fetchWrikeGroup(ctx context.Context, cfg Config, secrets Secrets, groupID string) (*wrikeGroup, error) {
	endpoint := fmt.Sprintf("%s/api/v4/groups/%s", c.baseURL(cfg), url.PathEscape(strings.TrimSpace(groupID)))
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
		return nil, fmt.Errorf("wrike: fetch group status %d: %s", status, string(body))
	}
	var envelope struct {
		Data []wrikeGroup `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("wrike: decode group: %w", err)
	}
	if len(envelope.Data) == 0 {
		return nil, nil
	}
	g := envelope.Data[0]
	return &g, nil
}

func (c *WrikeAccessConnector) userAlreadyInGroup(ctx context.Context, cfg Config, secrets Secrets, groupID, userID string) bool {
	group, err := c.fetchWrikeGroup(ctx, cfg, secrets, groupID)
	if err != nil || group == nil {
		return false
	}
	user := strings.TrimSpace(userID)
	for _, mid := range group.MemberIDs {
		if strings.EqualFold(strings.TrimSpace(mid), user) {
			return true
		}
	}
	return false
}

func wrikeOptionalGroupID(raw map[string]interface{}) string {
	if raw == nil {
		return ""
	}
	if v, ok := raw["group_id"].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}
