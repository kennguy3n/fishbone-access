package jfrog

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

// advanced-capability mapping for JFrog Platform Access:
//
//   - ProvisionAccess  -> PUT    /access/api/v2/users/{username}/groups/{group}
//   - RevokeAccess     -> DELETE /access/api/v2/users/{username}/groups/{group}
//   - ListEntitlements -> GET    /access/api/v2/users/{username}/groups
//
// AccessGrant maps:
//   - grant.UserExternalID     -> {username}
//   - grant.ResourceExternalID -> {group} name
//   - grant.Role               -> round-tripped on the Entitlement
//
// JFrog group membership is idempotent on the server side: PUT-ing an
// existing membership returns 200/204, and DELETE on a non-member
// returns 404 / 400 "does not exist", both of which are recognised by
// the idempotency helpers as success per docs/architecture.md §2.

func jfrogValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("jfrog: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("jfrog: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *JFrogAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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

func (c *JFrogAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("jfrog: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

// ProvisionAccess adds the user to the group. Idempotent on the
// (user, group) pair per docs/architecture.md §2.
func (c *JFrogAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := jfrogValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	username := url.PathEscape(strings.TrimSpace(grant.UserExternalID))
	group := url.PathEscape(strings.TrimSpace(grant.ResourceExternalID))
	full := fmt.Sprintf("%s/access/api/v2/users/%s/groups/%s", c.baseURL(cfg), username, group)
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPut, full, nil)
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
		return fmt.Errorf("jfrog: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("jfrog: provision status %d: %s", status, string(body))
	}
}

// RevokeAccess removes the user from the group. 404 / "not found"
// responses are idempotent success.
func (c *JFrogAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := jfrogValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	username := url.PathEscape(strings.TrimSpace(grant.UserExternalID))
	group := url.PathEscape(strings.TrimSpace(grant.ResourceExternalID))
	full := fmt.Sprintf("%s/access/api/v2/users/%s/groups/%s", c.baseURL(cfg), username, group)
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodDelete, full, nil)
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
		return fmt.Errorf("jfrog: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("jfrog: revoke status %d: %s", status, string(body))
	}
}

// ListEntitlements returns the groups the user is a member of.
func (c *JFrogAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("jfrog: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	full := fmt.Sprintf("%s/access/api/v2/users/%s/groups", c.baseURL(cfg), url.PathEscape(user))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodGet, full, nil)
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
		return nil, fmt.Errorf("jfrog: list groups status %d: %s", status, string(body))
	}
	var resp jfrogGroupsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("jfrog: decode groups: %w", err)
	}
	out := make([]access.Entitlement, 0, len(resp.Groups))
	for _, g := range resp.Groups {
		name := strings.TrimSpace(g.Name)
		if name == "" {
			name = strings.TrimSpace(g.GroupName)
		}
		if name == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: name,
			Role:               name,
			Source:             "direct",
		})
	}
	return out, nil
}

type jfrogGroupsResponse struct {
	Groups []struct {
		Name      string `json:"name,omitempty"`
		GroupName string `json:"group_name,omitempty"`
	} `json:"groups"`
}
