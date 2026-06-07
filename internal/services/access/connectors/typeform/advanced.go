package typeform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// typeformWorkspace models the workspace resource returned by
// GET /workspaces. Membership (email + role) lives in the nested `members`
// array — Typeform exposes no top-level per-user role field and no
// `/me/workspaces` route.
type typeformWorkspaceMember struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

type typeformWorkspace struct {
	ID      string                    `json:"id"`
	Members []typeformWorkspaceMember `json:"members"`
}

type typeformWorkspaceListResponse struct {
	Items     []typeformWorkspace `json:"items"`
	PageCount int                 `json:"page_count"`
}

// advanced-capability mapping for typeform:
//
//   - ProvisionAccess  -> POST   /workspaces/{workspace_id}/members
//   - RevokeAccess     -> DELETE /workspaces/{workspace_id}/members/{member_id}
//   - ListEntitlements -> GET    /workspaces (paginated; match nested members[])
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
	// Typeform has no "list one user's memberships" endpoint and no
	// `/me/workspaces` route — the authoritative source of a user's
	// workspace roles is the workspace resource itself, whose nested
	// `members` array carries each member's email + role (GET /workspaces).
	// Enumerate every workspace the token can see (paginated via
	// page/page_size) and collect the requested user's role in each. The
	// previous implementation hit a non-existent `/me/workspaces?email=`
	// path and read top-level `items[].email`/`items[].role`, which never
	// match real payloads (membership is nested), so it silently returned an
	// empty (false "no access") result for every user on the live API.
	const (
		pageSize           = 200
		maxEntitlementPage = 1000
	)
	var out []access.Entitlement
	for page := 1; page <= maxEntitlementPage; page++ {
		q := url.Values{}
		q.Set("page", strconv.Itoa(page))
		q.Set("page_size", strconv.Itoa(pageSize))
		req, err := c.newJSONRequest(ctx, secrets, http.MethodGet,
			c.baseURL()+"/workspaces?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		status, body, err := c.doRaw(req)
		if err != nil {
			return nil, err
		}
		if status == http.StatusNotFound {
			return out, nil
		}
		if status < 200 || status >= 300 {
			return nil, fmt.Errorf("typeform: list entitlements status %d: %s", status, string(body))
		}
		var resp typeformWorkspaceListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("typeform: decode entitlements: %w", err)
		}
		for i := range resp.Items {
			ws := &resp.Items[i]
			for _, m := range ws.Members {
				if !strings.EqualFold(strings.TrimSpace(m.Email), user) {
					continue
				}
				role := strings.TrimSpace(m.Role)
				if role == "" {
					role = "member"
				}
				out = append(out, access.Entitlement{
					ResourceExternalID: strings.TrimSpace(ws.ID) + ":" + role,
					Role:               role,
					Source:             "direct",
				})
				break // a user holds at most one membership per workspace
			}
		}
		// Stop at the last page. page_count is authoritative when the API
		// supplies it; otherwise fall back to the short-page heuristic.
		if len(resp.Items) == 0 {
			break
		}
		if resp.PageCount > 0 {
			if page >= resp.PageCount {
				break
			}
		} else if len(resp.Items) < pageSize {
			break
		}
	}
	return out, nil
}
