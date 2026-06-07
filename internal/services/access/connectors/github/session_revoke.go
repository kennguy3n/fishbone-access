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
	// doRaw returns a nil error for any 2xx, so err == nil already means
	// the removal propagated (covers the documented 204 as well as any
	// other 2xx such as 202 Accepted). 404 means the user was already
	// gone — idempotent success per the leaver contract.
	if err == nil {
		return nil
	}
	if resp != nil && resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return fmt.Errorf("github: session revoke: %w", err)
}
