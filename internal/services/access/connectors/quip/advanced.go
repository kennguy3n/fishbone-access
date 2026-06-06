package quip

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

// advanced-capability mapping for Quip:
//
//   - ProvisionAccess  -> POST /1/threads/add-members
//                         body: thread_id, member_ids[]
//   - RevokeAccess     -> POST /1/threads/remove-members
//                         body: thread_id, member_ids[]
//   - ListEntitlements -> GET  /1/threads/{thread_id}
//                         (member_ids include the user)
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Quip user_id
//   - grant.ResourceExternalID -> Quip thread_id (doc/folder shareable target)
//
// Bearer auth via QuipAccessConnector.newRequest.

func quipValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("quip: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("quip: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *QuipAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *QuipAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("quip: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *QuipAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := quipValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	form := url.Values{}
	form.Set("thread_id", strings.TrimSpace(grant.ResourceExternalID))
	form.Set("member_ids", strings.TrimSpace(grant.UserExternalID))
	endpoint := c.baseURL() + "/1/threads/add-members"
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPost, endpoint, []byte(form.Encode()))
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
		return fmt.Errorf("quip: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("quip: provision status %d: %s", status, string(body))
	}
}

func (c *QuipAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := quipValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	form := url.Values{}
	form.Set("thread_id", strings.TrimSpace(grant.ResourceExternalID))
	form.Set("member_ids", strings.TrimSpace(grant.UserExternalID))
	endpoint := c.baseURL() + "/1/threads/remove-members"
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPost, endpoint, []byte(form.Encode()))
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
		return fmt.Errorf("quip: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("quip: revoke status %d: %s", status, string(body))
	}
}

func (c *QuipAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("quip: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	threadID := quipOptionalThreadID(configRaw)
	if threadID == "" {
		return nil, errors.New("quip: thread_id is required in config for ListEntitlements")
	}
	endpoint := fmt.Sprintf("%s/1/threads/%s", c.baseURL(), url.PathEscape(threadID))
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
		return nil, fmt.Errorf("quip: list thread members status %d: %s", status, string(body))
	}
	var envelope struct {
		Thread struct {
			ID string `json:"id"`
		} `json:"thread"`
		UserIDs   []string `json:"user_ids"`
		MemberIDs []string `json:"member_ids"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("quip: decode thread: %w", err)
	}
	candidates := append([]string{}, envelope.UserIDs...)
	candidates = append(candidates, envelope.MemberIDs...)
	for _, id := range candidates {
		if strings.EqualFold(strings.TrimSpace(id), user) {
			return []access.Entitlement{{
				ResourceExternalID: threadID,
				Role:               "member",
				Source:             "direct",
			}}, nil
		}
	}
	return nil, nil
}

func quipOptionalThreadID(raw map[string]interface{}) string {
	if raw == nil {
		return ""
	}
	if v, ok := raw["thread_id"].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}
