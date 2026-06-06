package drift

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

// advanced-capability mapping for Drift:
//
// Drift's public REST surface does not expose a separate "membership"
// table; user permissions are attributes on the user record itself
// (role, availability, etc.). The mapping is therefore:
//
//   - ProvisionAccess  -> PATCH /v1/users/{user_id}      body {role}
//   - RevokeAccess     -> PATCH /v1/users/{user_id}      body {role: "REGULAR"}
//   - ListEntitlements -> GET   /v1/users/{user_id}      → role
//
// AccessGrant maps:
//   - grant.UserExternalID     -> {user_id}  (Drift numeric id)
//   - grant.ResourceExternalID -> role label (e.g. "ADMIN", "REGULAR")
//   - grant.Role               -> overrides ResourceExternalID if non-empty
//
// PATCH is naturally idempotent, so re-running ProvisionAccess with
// the same role is a no-op. RevokeAccess restores the default
// "REGULAR" role and 404 on a missing user is treated as success per
// docs/architecture.md §2.

const driftDefaultRole = "REGULAR"

func driftValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("drift: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" && strings.TrimSpace(g.Role) == "" {
		return errors.New("drift: grant.ResourceExternalID (role) is required")
	}
	return nil
}

func driftRole(g access.AccessGrant) string {
	if r := strings.TrimSpace(g.Role); r != "" {
		return r
	}
	return strings.TrimSpace(g.ResourceExternalID)
}

func (c *DriftAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *DriftAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("drift: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

// ProvisionAccess updates the user's role to grant.Role /
// ResourceExternalID. PATCH is naturally idempotent.
func (c *DriftAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := driftValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	userID := url.PathEscape(strings.TrimSpace(grant.UserExternalID))
	payload, _ := json.Marshal(map[string]string{"role": driftRole(grant)})
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPatch,
		c.baseURL()+"/v1/users/"+userID, payload)
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
		return fmt.Errorf("drift: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("drift: provision status %d: %s", status, string(body))
	}
}

// RevokeAccess restores the default "REGULAR" role. 404 on a
// non-existent user is treated as idempotent success per docs/architecture.md §2.
func (c *DriftAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := driftValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	userID := url.PathEscape(strings.TrimSpace(grant.UserExternalID))
	payload, _ := json.Marshal(map[string]string{"role": driftDefaultRole})
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPatch,
		c.baseURL()+"/v1/users/"+userID, payload)
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
		return fmt.Errorf("drift: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("drift: revoke status %d: %s", status, string(body))
	}
}

// ListEntitlements returns the current role bound to userExternalID
// as a single Entitlement.
func (c *DriftAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("drift: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet,
		c.baseURL()+"/v1/users/"+url.PathEscape(user))
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
		return nil, fmt.Errorf("drift: list entitlements status %d: %s", status, string(body))
	}
	var resp driftUserResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("drift: decode user: %w", err)
	}
	role := strings.TrimSpace(resp.Data.Role)
	if role == "" {
		role = driftDefaultRole
	}
	// Only surface non-default roles as a real entitlement so RevokeAccess
	// converges to an empty entitlement list (matching the broader
	// connector contract of "no grants => no entitlements").
	if strings.EqualFold(role, driftDefaultRole) {
		return nil, nil
	}
	return []access.Entitlement{{
		ResourceExternalID: role,
		Role:               role,
		Source:             "direct",
	}}, nil
}

type driftUserResponse struct {
	Data struct {
		ID   json.Number `json:"id"`
		Role string      `json:"role"`
	} `json:"data"`
}
