package squarespace

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
	"github.com/kennguy3n/fishbone-access/internal/services/access/httputil"
)

// advanced-capability mapping for Squarespace:
//
//   - ProvisionAccess  -> POST   /1.0/commerce/profile/members
//   - RevokeAccess     -> DELETE /1.0/commerce/profile/members/{id}
//   - ListEntitlements -> GET    /1.0/commerce/profile/members/{id}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Squarespace member id or email
//   - grant.ResourceExternalID -> member role (e.g. "subscriber", "contributor")
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func squarespaceValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("squarespace: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("squarespace: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *SquarespaceAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("squarespace: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *SquarespaceAccessConnector) membersURL() string {
	return c.baseURL() + "/1.0/commerce/profile/members"
}

func (c *SquarespaceAccessConnector) memberURL(memberID string) string {
	return c.baseURL() + "/1.0/commerce/profile/members/" + url.PathEscape(strings.TrimSpace(memberID))
}

func (c *SquarespaceAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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

func (c *SquarespaceAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := squarespaceValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"email": strings.TrimSpace(grant.UserExternalID),
		"role":  strings.TrimSpace(grant.ResourceExternalID),
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.membersURL(), payload)
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
		return fmt.Errorf("squarespace: provision transient status %d: %s", status, httputil.SafeErrorBody(body))
	default:
		return fmt.Errorf("squarespace: provision status %d: %s", status, httputil.SafeErrorBody(body))
	}
}

func (c *SquarespaceAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := squarespaceValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, c.memberURL(grant.UserExternalID), nil)
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
		return fmt.Errorf("squarespace: revoke transient status %d: %s", status, httputil.SafeErrorBody(body))
	default:
		return fmt.Errorf("squarespace: revoke status %d: %s", status, httputil.SafeErrorBody(body))
	}
}

func (c *SquarespaceAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("squarespace: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.memberURL(user), nil)
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
		return nil, fmt.Errorf("squarespace: list entitlements status %d: %s", status, httputil.SafeErrorBody(body))
	}
	var resp struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("squarespace: decode entitlements: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(resp.Email), user) &&
		strings.TrimSpace(resp.ID) != user {
		return nil, nil
	}
	role := strings.TrimSpace(resp.Role)
	if role == "" {
		return []access.Entitlement{}, nil
	}
	return []access.Entitlement{{
		ResourceExternalID: role,
		Role:               role,
		Source:             "direct",
	}}, nil
}
