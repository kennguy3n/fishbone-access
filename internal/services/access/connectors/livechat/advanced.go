package livechat

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

// advanced-capability mapping for LiveChat:
//
//   - ProvisionAccess  -> POST   /v3.5/agents
//                         body {id, role, suspended:false}
//   - RevokeAccess     -> DELETE /v3.5/agents/{agent_id}
//   - ListEntitlements -> GET    /v3.5/agents/{agent_id}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> LiveChat agent id (email-style)
//   - grant.ResourceExternalID -> LiveChat agent role (normal / administrator / owner / viceowner)
//
// PAT bearer auth via livechat.newRequest.

const liveChatDefaultRole = "normal"

func liveChatValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("livechat: grant.UserExternalID is required")
	}
	return nil
}

func liveChatRole(g access.AccessGrant) string {
	if r := strings.TrimSpace(g.Role); r != "" {
		return r
	}
	if r := strings.TrimSpace(g.ResourceExternalID); r != "" {
		return r
	}
	return liveChatDefaultRole
}

func (c *LiveChatAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.PAT))
	return req, nil
}

func (c *LiveChatAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("livechat: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *LiveChatAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := liveChatValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"id":        strings.TrimSpace(grant.UserExternalID),
		"role":      liveChatRole(grant),
		"suspended": false,
	})
	endpoint := c.baseURL() + "/v3.5/agents"
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPost, endpoint, payload)
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
		return fmt.Errorf("livechat: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("livechat: provision status %d: %s", status, string(body))
	}
}

func (c *LiveChatAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := liveChatValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/v3.5/agents/%s", c.baseURL(),
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
		return fmt.Errorf("livechat: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("livechat: revoke status %d: %s", status, string(body))
	}
}

func (c *LiveChatAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("livechat: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/v3.5/agents/%s", c.baseURL(), url.PathEscape(user))
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
		return nil, fmt.Errorf("livechat: list agent status %d: %s", status, string(body))
	}
	var resp liveChatAgent
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("livechat: decode agent: %w", err)
	}
	role := strings.TrimSpace(resp.Role)
	if role == "" {
		role = liveChatDefaultRole
	}
	return []access.Entitlement{{
		ResourceExternalID: role,
		Role:               role,
		Source:             "direct",
	}}, nil
}
