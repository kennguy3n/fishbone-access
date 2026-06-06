package docker_hub

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

// advanced-capability mapping for Docker Hub:
//
//   - ProvisionAccess  -> POST   /v2/orgs/{org}/groups/{group}/members
//   - RevokeAccess     -> DELETE /v2/orgs/{org}/groups/{group}/members/{username}
//   - ListEntitlements -> GET    /v2/orgs/{org}/members/{username}/groups
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Docker username
//   - grant.ResourceExternalID -> group name within the configured org
//   - grant.Role               -> "member" (Docker Hub doesn't expose
//     a per-group role; round-tripped on the resulting Entitlement)

func dockerValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("docker_hub: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("docker_hub: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *DockerHubAccessConnector) newRequestWithBody(ctx context.Context, token, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("Authorization", "JWT "+token)
	return req, nil
}

func (c *DockerHubAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("docker_hub: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

// ProvisionAccess adds the user to the group. Idempotent on the
// (user, group) pair per docs/architecture.md §2.
func (c *DockerHubAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := dockerValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.login(ctx, secrets)
	if err != nil {
		return err
	}
	org := url.PathEscape(strings.TrimSpace(cfg.Organization))
	group := url.PathEscape(strings.TrimSpace(grant.ResourceExternalID))
	payload, _ := json.Marshal(map[string]string{"member": strings.TrimSpace(grant.UserExternalID)})
	full := fmt.Sprintf("%s/v2/orgs/%s/groups/%s/members", c.baseURL(), org, group)
	req, err := c.newRequestWithBody(ctx, token, http.MethodPost, full, payload)
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
		return fmt.Errorf("docker_hub: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("docker_hub: provision status %d: %s", status, string(body))
	}
}

// RevokeAccess removes the user from the group. 404 / "not found"
// responses are idempotent success.
func (c *DockerHubAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := dockerValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.login(ctx, secrets)
	if err != nil {
		return err
	}
	org := url.PathEscape(strings.TrimSpace(cfg.Organization))
	group := url.PathEscape(strings.TrimSpace(grant.ResourceExternalID))
	user := url.PathEscape(strings.TrimSpace(grant.UserExternalID))
	full := fmt.Sprintf("%s/v2/orgs/%s/groups/%s/members/%s", c.baseURL(), org, group, user)
	req, err := c.newRequestWithBody(ctx, token, http.MethodDelete, full, nil)
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
		return fmt.Errorf("docker_hub: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("docker_hub: revoke status %d: %s", status, string(body))
	}
}

// ListEntitlements returns the groups the user currently belongs to.
func (c *DockerHubAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("docker_hub: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	token, err := c.login(ctx, secrets)
	if err != nil {
		return nil, err
	}
	org := url.PathEscape(strings.TrimSpace(cfg.Organization))
	full := fmt.Sprintf("%s/v2/orgs/%s/members/%s/groups", c.baseURL(), org, url.PathEscape(user))
	req, err := c.newRequestWithBody(ctx, token, http.MethodGet, full, nil)
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
		return nil, fmt.Errorf("docker_hub: list groups status %d: %s", status, string(body))
	}
	var resp dockerGroupsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("docker_hub: decode groups: %w", err)
	}
	out := make([]access.Entitlement, 0, len(resp.Results))
	for _, g := range resp.Results {
		name := strings.TrimSpace(g.Name)
		if name == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: name,
			Role:               "member",
			Source:             "direct",
		})
	}
	return out, nil
}

type dockerGroupsResponse struct {
	Results []struct {
		Name string `json:"name"`
		ID   int    `json:"id"`
	} `json:"results"`
}
