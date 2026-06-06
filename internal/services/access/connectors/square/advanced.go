package square

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

// advanced-capability mapping for square:
//
//   - ProvisionAccess  -> POST  /v2/team-members
//     body: {"team_member": {"reference_id": email, "is_owner": false,
//                            "given_name": email}}
//   - RevokeAccess     -> PUT   /v2/team-members/{userID} with
//     {"team_member":{"status":"INACTIVE"}} (Square soft-deactivates).
//     Square's UpdateTeamMember endpoint is PUT, not POST — POST on
//     the per-id URL returns 404/405 in production.
//   - ListEntitlements -> GET   /v2/team-members/{userID}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Square team-member id
//   - grant.ResourceExternalID -> role/permission slug (manager|cashier|...)
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func squareValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("square: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("square: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *SquareAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("square: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *SquareAccessConnector) teamMembersURL() string {
	return c.baseURL() + "/v2/team-members"
}

func (c *SquareAccessConnector) teamMemberURL(userID string) string {
	return c.teamMembersURL() + "/" + url.PathEscape(strings.TrimSpace(userID))
}

func (c *SquareAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := squareValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"team_member": map[string]interface{}{
			"reference_id": strings.TrimSpace(grant.UserExternalID),
			"given_name":   strings.TrimSpace(grant.UserExternalID),
			"status":       "ACTIVE",
			"job_assignment": map[string]string{
				"role_id": strings.TrimSpace(grant.ResourceExternalID),
			},
		},
	})
	req, err := c.newRequest(ctx, secrets, http.MethodPost, c.teamMembersURL(), bytes.NewReader(payload))
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
		return fmt.Errorf("square: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("square: provision status %d: %s", status, string(body))
	}
}

func (c *SquareAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := squareValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"team_member": map[string]interface{}{
			"status": "INACTIVE",
		},
	})
	req, err := c.newRequest(ctx, secrets, http.MethodPut, c.teamMemberURL(grant.UserExternalID), bytes.NewReader(payload))
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
		return fmt.Errorf("square: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("square: revoke status %d: %s", status, string(body))
	}
}

func (c *SquareAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("square: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.teamMemberURL(user), nil)
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
		return nil, fmt.Errorf("square: list entitlements status %d: %s", status, string(body))
	}
	var envelope struct {
		TeamMember struct {
			ID            string `json:"id"`
			ReferenceID   string `json:"reference_id"`
			Status        string `json:"status"`
			JobAssignment struct {
				RoleID string `json:"role_id"`
			} `json:"job_assignment"`
		} `json:"team_member"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("square: decode entitlements: %w", err)
	}
	tm := envelope.TeamMember
	id := strings.TrimSpace(tm.ID)
	ref := strings.TrimSpace(tm.ReferenceID)
	if id != user && !strings.EqualFold(ref, user) {
		return nil, nil
	}
	if !strings.EqualFold(strings.TrimSpace(tm.Status), "ACTIVE") {
		return nil, nil
	}
	role := strings.TrimSpace(tm.JobAssignment.RoleID)
	if role == "" {
		return []access.Entitlement{}, nil
	}
	return []access.Entitlement{{
		ResourceExternalID: role,
		Role:               role,
		Source:             "direct",
	}}, nil
}
