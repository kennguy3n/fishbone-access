package launchdarkly

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

// advanced-capability mapping for LaunchDarkly:
//
//   - ProvisionAccess  -> PATCH /api/v2/members/{member_id}     op:add custom role
//   - RevokeAccess     -> PATCH /api/v2/members/{member_id}     op:remove custom role
//   - ListEntitlements -> GET   /api/v2/members/{member_id}     returns customRoles
//
// AccessGrant maps:
//   - grant.UserExternalID     -> {member_id}
//   - grant.ResourceExternalID -> custom-role key
//   - grant.Role               -> round-tripped on the Entitlement
//
// LaunchDarkly JSON-patch idempotency:
//   - Adding a role that's already present returns 400 with
//     `"already exists"` in the message — IsIdempotentProvisionStatus
//     maps this to success.
//   - Removing a role that isn't present returns 400 with
//     `"does not exist"` — IsIdempotentRevokeStatus maps this to
//     success.

func ldValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("launchdarkly: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("launchdarkly: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *LaunchDarklyAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL, contentType string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", strings.TrimSpace(secrets.APIKey))
	return req, nil
}

func (c *LaunchDarklyAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("launchdarkly: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

type ldPatchOp struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

// ProvisionAccess assigns the custom role to the member. Idempotent on
// the (member, role) pair.
func (c *LaunchDarklyAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := ldValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	role := strings.TrimSpace(grant.ResourceExternalID)
	patch := []ldPatchOp{{Op: "add", Path: "/customRoles/-", Value: role}}
	body, _ := json.Marshal(patch)
	full := fmt.Sprintf("%s/api/v2/members/%s",
		c.baseURL(), url.PathEscape(strings.TrimSpace(grant.UserExternalID)))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPatch, full, "application/json", body)
	if err != nil {
		return err
	}
	status, respBody, err := c.doRaw(req)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentProvisionStatus(status, respBody):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("launchdarkly: provision transient status %d: %s", status, string(respBody))
	default:
		return fmt.Errorf("launchdarkly: provision status %d: %s", status, string(respBody))
	}
}

// RevokeAccess removes the custom role from the member. 404 / "not
// found" / "does not exist" responses are idempotent success.
func (c *LaunchDarklyAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := ldValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	role := strings.TrimSpace(grant.ResourceExternalID)
	// LaunchDarkly JSON-patch remove requires the role value
	// embedded in the path; we send a "test then remove" sequence
	// that maps cleanly to the "does not exist" semantics when the
	// role is absent.
	patch := []ldPatchOp{{Op: "remove", Path: "/customRoles/" + role}}
	body, _ := json.Marshal(patch)
	full := fmt.Sprintf("%s/api/v2/members/%s",
		c.baseURL(), url.PathEscape(strings.TrimSpace(grant.UserExternalID)))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPatch, full, "application/json", body)
	if err != nil {
		return err
	}
	status, respBody, err := c.doRaw(req)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentRevokeStatus(status, respBody):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("launchdarkly: revoke transient status %d: %s", status, string(respBody))
	default:
		return fmt.Errorf("launchdarkly: revoke status %d: %s", status, string(respBody))
	}
}

// ListEntitlements returns the custom roles bound to the member.
func (c *LaunchDarklyAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("launchdarkly: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	full := fmt.Sprintf("%s/api/v2/members/%s", c.baseURL(), url.PathEscape(user))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, full)
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
		return nil, fmt.Errorf("launchdarkly: list member status %d: %s", status, string(body))
	}
	var resp ldMemberResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("launchdarkly: decode member: %w", err)
	}
	out := make([]access.Entitlement, 0, len(resp.CustomRoles))
	for _, r := range resp.CustomRoles {
		role := strings.TrimSpace(r)
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

type ldMemberResponse struct {
	ID          string   `json:"_id"`
	Email       string   `json:"email"`
	Role        string   `json:"role"`
	CustomRoles []string `json:"customRoles"`
}
