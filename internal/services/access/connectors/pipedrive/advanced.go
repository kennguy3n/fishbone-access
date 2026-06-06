package pipedrive

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

// advanced-capability mapping for Pipedrive:
//
//   - ProvisionAccess  -> POST   /v1/permissionSets/{set_id}/assignments
//   - RevokeAccess     -> DELETE /v1/permissionSets/{set_id}/assignments/{user_id}
//   - ListEntitlements -> GET    /v1/users/{user_id}/permissionSetAssignments
//
// baseURL() already includes the /v1 prefix, so the path arguments
// passed to newRequest / newRequestWithBody omit /v1 to avoid
// double-prefixing.
//
// AccessGrant maps:
//   - grant.UserExternalID     -> {user_id}
//   - grant.ResourceExternalID -> {set_id}
//   - grant.Role               -> permission-set display name (round-tripped)

func pipedriveValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("pipedrive: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("pipedrive: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *PipedriveAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, path string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.APIToken))
	return req, nil
}

func (c *PipedriveAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("pipedrive: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

// ProvisionAccess assigns the permission set identified by
// grant.ResourceExternalID to grant.UserExternalID.
func (c *PipedriveAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := pipedriveValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	setID := url.PathEscape(strings.TrimSpace(grant.ResourceExternalID))
	userID := strings.TrimSpace(grant.UserExternalID)
	payload, _ := json.Marshal(map[string]string{"user_id": userID})
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPost,
		"/permissionSets/"+setID+"/assignments", payload)
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
		return fmt.Errorf("pipedrive: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("pipedrive: provision status %d: %s", status, string(body))
	}
}

// RevokeAccess removes the permission-set assignment. 404 is treated
// as idempotent success per docs/architecture.md §2.
func (c *PipedriveAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := pipedriveValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	setID := url.PathEscape(strings.TrimSpace(grant.ResourceExternalID))
	userID := url.PathEscape(strings.TrimSpace(grant.UserExternalID))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodDelete,
		"/permissionSets/"+setID+"/assignments/"+userID, nil)
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
		return fmt.Errorf("pipedrive: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("pipedrive: revoke status %d: %s", status, string(body))
	}
}

// ListEntitlements returns the permission sets currently bound to the
// user as Entitlement entries.
func (c *PipedriveAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("pipedrive: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet,
		"/users/"+url.PathEscape(user)+"/permissionSetAssignments")
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
		return nil, fmt.Errorf("pipedrive: list entitlements status %d: %s", status, string(body))
	}
	var resp pipedriveAssignmentsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("pipedrive: decode assignments: %w", err)
	}
	if !resp.Success {
		return nil, nil
	}
	out := make([]access.Entitlement, 0, len(resp.Data))
	for _, a := range resp.Data {
		id := strings.TrimSpace(a.ID)
		if id == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: id,
			Role:               a.Name,
			Source:             "direct",
		})
	}
	return out, nil
}

type pipedriveAssignmentsResponse struct {
	Success bool                     `json:"success"`
	Data    []pipedriveAssignmentEnt `json:"data"`
}

type pipedriveAssignmentEnt struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
