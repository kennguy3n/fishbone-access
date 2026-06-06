package loom

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

// advanced-capability mapping for Loom:
//
//   - ProvisionAccess  -> POST   /v1/members         body {email, role}
//   - RevokeAccess     -> DELETE /v1/members/{user_id}
//   - ListEntitlements -> GET    /v1/members?email={email}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Loom member email (preferred) or member id
//   - grant.ResourceExternalID -> Loom role (member / admin / owner)
//
// Bearer auth via loom.newRequest.

const loomDefaultRole = "member"

func loomValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("loom: grant.UserExternalID is required")
	}
	return nil
}

func loomRole(g access.AccessGrant) string {
	if r := strings.TrimSpace(g.Role); r != "" {
		return r
	}
	if r := strings.TrimSpace(g.ResourceExternalID); r != "" {
		return r
	}
	return loomDefaultRole
}

func (c *LoomAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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

func (c *LoomAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("loom: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *LoomAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := loomValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"email": strings.TrimSpace(grant.UserExternalID),
		"role":  loomRole(grant),
	})
	endpoint := c.baseURL() + "/v1/members"
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
		return fmt.Errorf("loom: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("loom: provision status %d: %s", status, string(body))
	}
}

func (c *LoomAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := loomValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	id, err := c.findLoomMemberID(ctx, secrets, grant.UserExternalID)
	if err != nil {
		return err
	}
	if id == "" {
		return nil
	}
	endpoint := fmt.Sprintf("%s/v1/members/%s", c.baseURL(), url.PathEscape(id))
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
		return fmt.Errorf("loom: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("loom: revoke status %d: %s", status, string(body))
	}
}

func (c *LoomAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("loom: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	matches, err := c.listLoomMembersByEmail(ctx, secrets, user)
	if err != nil {
		return nil, err
	}
	// Loom workspace members carry a single role at a time, so
	// the first match is the authoritative entitlement.
	if len(matches) == 0 {
		return nil, nil
	}
	role := strings.TrimSpace(matches[0].Role)
	if role == "" {
		role = loomDefaultRole
	}
	return []access.Entitlement{{
		ResourceExternalID: role,
		Role:               role,
		Source:             "direct",
	}}, nil
}

func (c *LoomAccessConnector) findLoomMemberID(ctx context.Context, secrets Secrets, identifier string) (string, error) {
	matches, err := c.listLoomMembersByEmail(ctx, secrets, identifier)
	if err != nil {
		return "", err
	}
	for i := range matches {
		if id := strings.TrimSpace(matches[i].ID); id != "" {
			return id, nil
		}
	}
	return "", nil
}

func (c *LoomAccessConnector) listLoomMembersByEmail(ctx context.Context, secrets Secrets, email string) ([]loomMember, error) {
	q := url.Values{}
	q.Set("email", strings.TrimSpace(email))
	endpoint := fmt.Sprintf("%s/v1/members?%s", c.baseURL(), q.Encode())
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
		return nil, fmt.Errorf("loom: list members status %d: %s", status, string(body))
	}
	var resp loomListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("loom: decode members: %w", err)
	}
	out := make([]loomMember, 0, len(resp.Data))
	for i := range resp.Data {
		if strings.EqualFold(strings.TrimSpace(resp.Data[i].Email), strings.TrimSpace(email)) {
			out = append(out, resp.Data[i])
		}
	}
	return out, nil
}
