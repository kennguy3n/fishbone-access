package billdotcom

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

// advanced-capability mapping for billdotcom:
//
//   - ProvisionAccess  -> POST   /v3/orgs/{org_id}/users
//                         body {email, role}
//   - RevokeAccess     -> DELETE /v3/orgs/{org_id}/users/{user_id}
//   - ListEntitlements -> GET    /v3/orgs/{org_id}/users?email=...
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Bill.com user id (or email — see below)
//   - grant.ResourceExternalID -> Bill.com role (e.g. "ADMIN", "ACCOUNTANT")
//
// Auth reuses the existing newRequest helper (devKey + sessionId
// headers). Idempotent on (UserExternalID, ResourceExternalID) per
// docs/architecture.md §2 — Bill.com returns 409 / 422 "already" on duplicate
// invites and 404 on already-deleted users.

func billdotcomValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("billdotcom: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("billdotcom: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *BillDotComAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("billdotcom: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *BillDotComAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("devKey", strings.TrimSpace(secrets.DevKey))
	req.Header.Set("sessionId", strings.TrimSpace(secrets.SessionToken))
	return req, nil
}

func (c *BillDotComAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := billdotcomValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{
		"email": strings.TrimSpace(grant.UserExternalID),
		"role":  strings.TrimSpace(grant.ResourceExternalID),
	})
	endpoint := c.baseURL() + c.buildPath(cfg)
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, endpoint, payload)
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
		return fmt.Errorf("billdotcom: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("billdotcom: provision status %d: %s", status, string(body))
	}
}

func (c *BillDotComAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := billdotcomValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := c.baseURL() + c.buildPath(cfg) + "/" + url.PathEscape(strings.TrimSpace(grant.UserExternalID))
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
		return fmt.Errorf("billdotcom: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("billdotcom: revoke status %d: %s", status, string(body))
	}
}

type billUserDetail struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	Active    bool   `json:"active"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type billUserListResponse struct {
	Users []billUserDetail `json:"users"`
}

func (c *BillDotComAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("billdotcom: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	q := url.Values{"email": []string{user}}
	endpoint := c.baseURL() + c.buildPath(cfg) + "?" + q.Encode()
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
		return nil, fmt.Errorf("billdotcom: list entitlements status %d: %s", status, string(body))
	}
	var resp billUserListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("billdotcom: decode users: %w", err)
	}
	out := make([]access.Entitlement, 0, len(resp.Users))
	for _, u := range resp.Users {
		if !u.Active {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(u.ID), user) &&
			!strings.EqualFold(strings.TrimSpace(u.Email), user) {
			continue
		}
		role := strings.TrimSpace(u.Role)
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
