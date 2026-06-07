package liquidplanner

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

// advanced-capability mapping for LiquidPlanner:
//
//   - ProvisionAccess  -> POST   /api/v1/workspaces/{workspace_id}/members
//                         body { email, access_level }
//   - RevokeAccess     -> DELETE /api/v1/workspaces/{workspace_id}/members/{member_id}
//   - ListEntitlements -> GET    /api/v1/workspaces/{workspace_id}/members
//
// AccessGrant maps:
//   - grant.UserExternalID     -> LiquidPlanner email address (preferred) or numeric member id
//   - grant.ResourceExternalID -> LiquidPlanner workspace id
//
// SyncIdentities sets each identity's ExternalID to the numeric member id, so a
// synced identifier flowing into ProvisionAccess looks like "77" rather than an
// email. The create-member endpoint requires an email, so when the identifier
// is numeric we resolve it via the existing /members listing before POSTing.
//
// Bearer auth via LiquidPlannerAccessConnector.newRequest.

func liquidplannerValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("liquidplanner: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("liquidplanner: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *LiquidPlannerAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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

func (c *LiquidPlannerAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("liquidplanner: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *LiquidPlannerAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := liquidplannerValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	// Pre-check is best-effort here: a transient lookup error is tolerated
	// because a real duplicate POST is absorbed by IsIdempotentProvisionStatus
	// below. RevokeAccess uses the strict variant to avoid silently no-opping
	// on transient errors.
	if _, ok, _ := c.findLiquidplannerMember(ctx, cfg, secrets, grant.UserExternalID); ok {
		return nil
	}
	email, err := c.resolveLiquidplannerEmail(ctx, cfg, secrets, grant.UserExternalID)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"email":        email,
		"access_level": "member",
	})
	endpoint := fmt.Sprintf("%s/api/v1/workspaces/%s/members",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(grant.ResourceExternalID)))
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
		return fmt.Errorf("liquidplanner: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("liquidplanner: provision status %d: %s", status, string(body))
	}
}

func (c *LiquidPlannerAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := liquidplannerValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	// Strict pre-check: a transient /members fetch failure must NOT silently
	// succeed as "already revoked" — that would let a network blip leave the
	// user with workspace access while reporting a successful revoke to the
	// caller. Propagate the error so the caller can retry.
	memberID, ok, err := c.findLiquidplannerMember(ctx, cfg, secrets, grant.UserExternalID)
	if err != nil {
		return fmt.Errorf("liquidplanner: revoke pre-check: %w", err)
	}
	if !ok || memberID == "" {
		return nil
	}
	endpoint := fmt.Sprintf("%s/api/v1/workspaces/%s/members/%s",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(grant.ResourceExternalID)),
		url.PathEscape(memberID))
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
		return fmt.Errorf("liquidplanner: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("liquidplanner: revoke status %d: %s", status, string(body))
	}
}

func (c *LiquidPlannerAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("liquidplanner: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	members, err := c.fetchLiquidplannerMembers(ctx, cfg, secrets)
	if err != nil {
		return nil, err
	}
	for i := range members {
		if strings.EqualFold(strings.TrimSpace(members[i].EmailAddr), user) ||
			fmt.Sprintf("%d", members[i].ID) == user {
			role := strings.TrimSpace(members[i].AccessLevel)
			if role == "" {
				role = "member"
			}
			return []access.Entitlement{{
				ResourceExternalID: strings.TrimSpace(cfg.WorkspaceID),
				Role:               role,
				Source:             "direct",
			}}, nil
		}
	}
	return nil, nil
}

func (c *LiquidPlannerAccessConnector) fetchLiquidplannerMembers(ctx context.Context, cfg Config, secrets Secrets) ([]liquidplannerMember, error) {
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.membersURL(cfg))
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
		return nil, fmt.Errorf("liquidplanner: list members status %d: %s", status, string(body))
	}
	var members []liquidplannerMember
	if err := json.Unmarshal(body, &members); err != nil {
		return nil, fmt.Errorf("liquidplanner: decode members: %w", err)
	}
	return members, nil
}

// findLiquidplannerMember returns (memberID, found, err). Callers MUST treat
// a non-nil err as "lookup failed" rather than "user absent"; otherwise a
// transient /members failure during RevokeAccess would silently return
// success while the user retains workspace access. ProvisionAccess may
// safely ignore the error and fall through to the create POST, because the
// idempotency-status handler absorbs duplicate-member responses.
func (c *LiquidPlannerAccessConnector) findLiquidplannerMember(ctx context.Context, cfg Config, secrets Secrets, identifier string) (string, bool, error) {
	members, err := c.fetchLiquidplannerMembers(ctx, cfg, secrets)
	if err != nil {
		return "", false, err
	}
	id := strings.TrimSpace(identifier)
	for i := range members {
		if strings.EqualFold(strings.TrimSpace(members[i].EmailAddr), id) ||
			fmt.Sprintf("%d", members[i].ID) == id {
			return fmt.Sprintf("%d", members[i].ID), true, nil
		}
	}
	return "", false, nil
}

// resolveLiquidplannerEmail returns the email to send in the create-member
// POST body. An identifier containing "@" is treated as an email and used
// verbatim; a numeric identifier is resolved by looking up the matching
// member record. If no email can be resolved, an explicit error is returned
// rather than letting a numeric id leak into the email field.
func (c *LiquidPlannerAccessConnector) resolveLiquidplannerEmail(ctx context.Context, cfg Config, secrets Secrets, identifier string) (string, error) {
	id := strings.TrimSpace(identifier)
	if strings.Contains(id, "@") {
		return id, nil
	}
	members, err := c.fetchLiquidplannerMembers(ctx, cfg, secrets)
	if err != nil {
		return "", err
	}
	for i := range members {
		if fmt.Sprintf("%d", members[i].ID) == id {
			if e := strings.TrimSpace(members[i].EmailAddr); e != "" {
				return e, nil
			}
		}
	}
	return "", fmt.Errorf("liquidplanner: provision requires an email; got non-email identifier %q with no matching workspace member", id)
}
