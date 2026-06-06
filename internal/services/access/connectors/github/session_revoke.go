package github

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// RevokeUserSessions implements access.SessionRevoker for GitHub.
// GitHub has no per-user "kill every session" REST endpoint, so
// the canonical kill switch for a leaver is to remove the user
// from the org via DELETE /orgs/{org}/memberships/{username}. This
// invalidates every org-scoped personal access token and SSO
// session the user had against the org.
//
// userExternalID is the GitHub login (the SyncIdentities-emitted
// external_id). 204 from GitHub means propagated; 404 means the
// user was already removed and is treated as success (idempotent
// kill switch per the leaver contract).
func (c *GitHubAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	if userExternalID == "" {
		return fmt.Errorf("github: session revoke: userExternalID is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	target := fmt.Sprintf("%s/orgs/%s/memberships/%s",
		c.baseURL(), url.PathEscape(cfg.Organization), url.PathEscape(userExternalID))
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, target)
	if err != nil {
		return err
	}
	resp, err := c.doRaw(req)
	if err == nil && (resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK) {
		return nil
	}
	if resp != nil && resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if err != nil {
		return fmt.Errorf("github: session revoke: %w", err)
	}
	return fmt.Errorf("github: session revoke status %d", resp.StatusCode)
}
