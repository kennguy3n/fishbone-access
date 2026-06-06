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
	// SyncIdentities exports the member ID as the canonical ExternalID, so
	// revoke calls from the JML pipeline normally arrive keyed by ID. Only
	// resolve via the email lookup when the identifier actually looks like
	// an email; otherwise treat it as the member ID and DELETE directly so
	// we never silently no-op a real revoke (a 404 is handled as an
	// idempotent "already revoked" below).
	id := strings.TrimSpace(grant.UserExternalID)
	if strings.Contains(id, "@") {
		resolved, err := c.findLoomMemberID(ctx, secrets, id)
		if err != nil {
			return err
		}
		if resolved == "" {
			return nil
		}
		id = resolved
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
	// Resolve by email or member ID: SyncIdentities exports the member ID
	// as ExternalID, so entitlement lookups from the access graph arrive
	// keyed by ID, which the ?email= filter would never match.
	member, ok, err := c.resolveLoomMember(ctx, secrets, user)
	if err != nil {
		return nil, err
	}
	// Loom workspace members carry a single role at a time, so
	// the resolved member is the authoritative entitlement.
	if !ok {
		return nil, nil
	}
	role := strings.TrimSpace(member.Role)
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

// resolveLoomMember finds a workspace member by email (via the ?email=
// filter) or by member ID (by paging the member list). SyncIdentities
// exports the member ID as the canonical ExternalID, so revoke/list
// calls from the JML pipeline arrive keyed by ID; resolving by email
// alone would silently miss them.
func (c *LoomAccessConnector) resolveLoomMember(ctx context.Context, secrets Secrets, identifier string) (loomMember, bool, error) {
	id := strings.TrimSpace(identifier)
	if id == "" {
		return loomMember{}, false, nil
	}
	if strings.Contains(id, "@") {
		matches, err := c.listLoomMembersByEmail(ctx, secrets, id)
		if err != nil {
			return loomMember{}, false, err
		}
		if len(matches) == 0 {
			return loomMember{}, false, nil
		}
		return matches[0], true, nil
	}
	return c.findLoomMemberByID(ctx, secrets, id)
}

// findLoomMemberByID pages the member list and returns the member whose
// ID matches. Loom's member list endpoint exposes no by-ID filter, so we
// page (cursor) and match client-side.
func (c *LoomAccessConnector) findLoomMemberByID(ctx context.Context, secrets Secrets, memberID string) (loomMember, bool, error) {
	base := c.baseURL()
	cursor := ""
	for {
		path := fmt.Sprintf("%s/v1/members?limit=%d", base, pageSize)
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return loomMember{}, false, err
		}
		status, body, err := c.doRaw(req)
		if err != nil {
			return loomMember{}, false, err
		}
		if status == http.StatusNotFound {
			return loomMember{}, false, nil
		}
		if status < 200 || status >= 300 {
			return loomMember{}, false, fmt.Errorf("loom: list members status %d: %s", status, string(body))
		}
		var resp loomListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return loomMember{}, false, fmt.Errorf("loom: decode members: %w", err)
		}
		for i := range resp.Data {
			if strings.TrimSpace(resp.Data[i].ID) == memberID {
				return resp.Data[i], true, nil
			}
		}
		if resp.NextCursor == "" {
			return loomMember{}, false, nil
		}
		cursor = resp.NextCursor
	}
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
