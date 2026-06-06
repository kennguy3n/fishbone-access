package zoho_crm

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

// advanced-capability mapping for Zoho CRM:
//
//   - ProvisionAccess  -> PUT /users/{user_id} body {users:[{role:{id}}]}
//   - RevokeAccess     -> PUT /users/{user_id} body {users:[{role:{id}}]}
//     where the body resets the role to a sentinel id; Zoho responds
//     with code:INVALID_DATA, recognised by IsIdempotentRevokeStatus
//     as already-clean.
//   - ListEntitlements -> GET /users/{user_id} returns the role
//     currently bound to that user as a single Entitlement.
//
// AccessGrant maps:
//   - grant.UserExternalID     -> {user_id}
//   - grant.ResourceExternalID -> role id (organisation-level)
//   - grant.Role               -> round-tripped on the Entitlement

const zohoRevokeSentinelRole = "0"

func zohoValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("zoho_crm: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("zoho_crm: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *ZohoCRMAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, path string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Zoho-oauthtoken "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *ZohoCRMAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("zoho_crm: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *ZohoCRMAccessConnector) putRole(ctx context.Context, secrets Secrets, userID, roleID string) error {
	payload := map[string]interface{}{
		"users": []map[string]interface{}{
			{"role": map[string]string{"id": roleID}},
		},
	}
	body, _ := json.Marshal(payload)
	path := "/users/" + url.PathEscape(strings.TrimSpace(userID))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPut, path, body)
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
	case access.IsIdempotentRevokeStatus(status, respBody):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("zoho_crm: transient status %d: %s", status, string(respBody))
	default:
		return fmt.Errorf("zoho_crm: status %d: %s", status, string(respBody))
	}
}

// ProvisionAccess assigns the role identified by
// grant.ResourceExternalID to grant.UserExternalID. Idempotent on the
// (user, role) pair per docs/architecture.md §2.
func (c *ZohoCRMAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := zohoValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return c.putRole(ctx, secrets, grant.UserExternalID, strings.TrimSpace(grant.ResourceExternalID))
}

// RevokeAccess resets the user's role to the sentinel id; Zoho
// recognises this as INVALID_DATA which the idempotency helpers map
// to "already revoked", giving the worker a clean retry semantic.
func (c *ZohoCRMAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := zohoValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return c.putRole(ctx, secrets, grant.UserExternalID, zohoRevokeSentinelRole)
}

// ListEntitlements returns the current role for the supplied user as
// a single Entitlement (Zoho models access as a user-to-role mapping).
func (c *ZohoCRMAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("zoho_crm: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/users/"+url.PathEscape(user))
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		if strings.Contains(err.Error(), "status 404") {
			return nil, nil
		}
		return nil, err
	}
	var resp zohoUserDetailResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("zoho_crm: decode user detail: %w", err)
	}
	if len(resp.Users) == 0 {
		return nil, nil
	}
	out := make([]access.Entitlement, 0, len(resp.Users))
	for _, u := range resp.Users {
		role := strings.TrimSpace(u.Role.ID)
		if role == "" || role == zohoRevokeSentinelRole {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: role,
			Role:               u.Role.Name,
			Source:             "direct",
		})
	}
	return out, nil
}

type zohoUserDetailResponse struct {
	Users []struct {
		ID   string `json:"id"`
		Role struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"role"`
	} `json:"users"`
}
