// Package docker_hub — SessionRevoker via org-member removal.
//
// Docker Hub does not expose a session-only revocation API; the
// closest kill switch is removing the user from the organisation:
//
//	DELETE /v2/orgs/{name}/members/{username}
//
// Removal terminates the user's Docker Hub Business access (image
// pulls / pushes / private repository visibility) and forces re-auth
// against the IdP-federated login if the org is SSO-enabled. The
// removed user retains a personal Docker ID but cannot access org
// resources. 404 is treated as idempotent success (the member is
// already gone). userExternalID is the upstream username
// (case-insensitive in Docker Hub's API but lower-case in the URL).
package docker_hub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func (c *DockerHubAccessConnector) RevokeUserSessions(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) error {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return errors.New("docker_hub: session revoke: userExternalID is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	org := strings.TrimSpace(cfg.Organization)
	if org == "" {
		return errors.New("docker_hub: session revoke: organization is required")
	}
	token, err := c.login(ctx, secrets)
	if err != nil {
		return err
	}
	target := fmt.Sprintf("%s/v2/orgs/%s/members/%s",
		c.baseURL(), url.PathEscape(org), url.PathEscape(strings.ToLower(userExternalID)))
	req, err := c.newRequest(ctx, token, http.MethodDelete, target)
	if err != nil {
		return err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("docker_hub: session revoke: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusAccepted, http.StatusNotFound:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	return fmt.Errorf("docker_hub: session revoke status %d: %s", resp.StatusCode, string(body))
}

var _ access.SessionRevoker = (*DockerHubAccessConnector)(nil)
