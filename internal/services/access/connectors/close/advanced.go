package close

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// advanced-capability mapping for close.com:
//
//   - ProvisionAccess  -> POST   /api/v1/role_assignment/   (body: user_id, role_id)
//   - RevokeAccess     -> GET    /api/v1/role_assignment/?user_id={userId} then
//                         DELETE /api/v1/role_assignment/{resolved_assignment_id}/
//   - ListEntitlements -> GET    /api/v1/role_assignment/?user_id={userId}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Close user id
//   - grant.ResourceExternalID -> Close role id (consistent across all three
//                                 methods so the (user, resource) pair round-trips).
//
// HTTP Basic auth with api_key:<blank> mirrors the existing
// connector.newRequest helper. Idempotent on
// (UserExternalID, ResourceExternalID).

func closeValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("close: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("close: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *CloseAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("close: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *CloseAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	creds := strings.TrimSpace(secrets.APIKey) + ":"
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *CloseAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := closeValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{
		"user_id": strings.TrimSpace(grant.UserExternalID),
		"role_id": strings.TrimSpace(grant.ResourceExternalID),
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.baseURL()+"/api/v1/role_assignment/", payload)
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
		return fmt.Errorf("close: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("close: provision status %d: %s", status, string(body))
	}
}

func (c *CloseAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := closeValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	userID := strings.TrimSpace(grant.UserExternalID)
	roleID := strings.TrimSpace(grant.ResourceExternalID)

	assignmentID, err := c.findRoleAssignmentID(ctx, secrets, userID, roleID)
	if err != nil {
		return err
	}
	if assignmentID == "" {
		// No matching assignment found — already revoked. Idempotent per docs/architecture.md §2.
		return nil
	}

	endpoint := c.baseURL() + "/api/v1/role_assignment/" + url.PathEscape(assignmentID) + "/"
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, endpoint, nil)
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
		return fmt.Errorf("close: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("close: revoke status %d: %s", status, string(body))
	}
}

// findRoleAssignmentID resolves the assignment record id for a given
// (userID, roleID) pair by querying the list endpoint. Returns an empty
// string if no match is found — callers should treat that as already-revoked.
func (c *CloseAccessConnector) findRoleAssignmentID(ctx context.Context, secrets Secrets, userID, roleID string) (string, error) {
	q := url.Values{}
	q.Set("user_id", userID)
	endpoint := c.baseURL() + "/api/v1/role_assignment/?" + q.Encode()
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return "", err
	}
	if status == http.StatusNotFound {
		return "", nil
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("close: lookup role_assignment status %d: %s", status, string(body))
	}
	var envelope struct {
		Data []struct {
			ID     string `json:"id"`
			UserID string `json:"user_id"`
			RoleID string `json:"role_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", fmt.Errorf("close: decode role_assignment lookup: %w", err)
	}
	for _, d := range envelope.Data {
		if strings.TrimSpace(d.UserID) == userID && strings.TrimSpace(d.RoleID) == roleID {
			return strings.TrimSpace(d.ID), nil
		}
	}
	return "", nil
}

func (c *CloseAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("close: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("user_id", user)
	endpoint := c.baseURL() + "/api/v1/role_assignment/?" + q.Encode()
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, endpoint, nil)
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
		return nil, fmt.Errorf("close: list entitlements status %d: %s", status, string(body))
	}
	var envelope struct {
		Data []struct {
			ID     string `json:"id"`
			UserID string `json:"user_id"`
			RoleID string `json:"role_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("close: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0, len(envelope.Data))
	for _, d := range envelope.Data {
		if strings.TrimSpace(d.UserID) != user {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: strings.TrimSpace(d.RoleID),
			Role:               strings.TrimSpace(d.RoleID),
			Source:             "direct",
		})
	}
	return out, nil
}
