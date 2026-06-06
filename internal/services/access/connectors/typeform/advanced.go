package typeform

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

// advanced-capability mapping for typeform:
//
//   - ProvisionAccess  -> POST   /workspaces/{workspace_id}/members
//   - RevokeAccess     -> DELETE /workspaces/{workspace_id}/members/{member_id}
//   - ListEntitlements -> GET    /workspaces/{workspace_id}/members/{member_id}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Typeform member email or ID
//   - grant.ResourceExternalID -> workspace ID + ":" + role (workspaceID:role)
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func typeformValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("typeform: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("typeform: grant.ResourceExternalID is required")
	}
	return nil
}

func typeformSplitResource(resourceExternalID string) (workspaceID, role string) {
	v := strings.TrimSpace(resourceExternalID)
	if i := strings.Index(v, ":"); i >= 0 {
		return strings.TrimSpace(v[:i]), strings.TrimSpace(v[i+1:])
	}
	return v, "member"
}

func (c *TypeformAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("typeform: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *TypeformAccessConnector) workspaceMembersURL(workspaceID string) string {
	return c.baseURL() + "/workspaces/" + url.PathEscape(strings.TrimSpace(workspaceID)) + "/members"
}

func (c *TypeformAccessConnector) workspaceMemberURL(workspaceID, memberID string) string {
	return c.workspaceMembersURL(workspaceID) + "/" + url.PathEscape(strings.TrimSpace(memberID))
}

func (c *TypeformAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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

func (c *TypeformAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := typeformValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	workspaceID, role := typeformSplitResource(grant.ResourceExternalID)
	if workspaceID == "" {
		return errors.New("typeform: ResourceExternalID must include workspace id")
	}
	payload, _ := json.Marshal(map[string]string{
		"email": strings.TrimSpace(grant.UserExternalID),
		"role":  role,
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.workspaceMembersURL(workspaceID), payload)
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
		return fmt.Errorf("typeform: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("typeform: provision status %d: %s", status, string(body))
	}
}

func (c *TypeformAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := typeformValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	workspaceID, _ := typeformSplitResource(grant.ResourceExternalID)
	if workspaceID == "" {
		return errors.New("typeform: ResourceExternalID must include workspace id")
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete,
		c.workspaceMemberURL(workspaceID, grant.UserExternalID), nil)
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
		return fmt.Errorf("typeform: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("typeform: revoke status %d: %s", status, string(body))
	}
}

func (c *TypeformAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("typeform: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	// Without a workspace context we cannot disambiguate; iterate over configured workspace
	// from /me to surface workspace memberships. For our purposes, fetch /me and report
	// any workspace memberships returned by the API for the user.
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet,
		c.baseURL()+"/me/workspaces?email="+url.QueryEscape(user), nil)
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
		return nil, fmt.Errorf("typeform: list entitlements status %d: %s", status, string(body))
	}
	var resp struct {
		Items []struct {
			ID    string `json:"id"`
			Role  string `json:"role"`
			Email string `json:"email"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("typeform: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0, len(resp.Items))
	for _, m := range resp.Items {
		if !strings.EqualFold(strings.TrimSpace(m.Email), user) {
			continue
		}
		role := strings.TrimSpace(m.Role)
		if role == "" {
			role = "member"
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: strings.TrimSpace(m.ID) + ":" + role,
			Role:               role,
			Source:             "direct",
		})
	}
	return out, nil
}
