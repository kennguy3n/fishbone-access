package jira

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// RevokeUserSessions implements access.SessionRevoker for Jira /
// Atlassian Cloud. Atlassian does not expose a per-user session
// invalidation endpoint on the Jira site REST API, so the canonical
// strategy is to POST the Atlassian Admin user-lifecycle
// deactivation endpoint:
//
//	POST https://api.atlassian.com/users/{accountId}/manage/lifecycle/disable
//
// The endpoint deactivates the Atlassian account, which invalidates
// every active session and refresh token across Jira / Confluence /
// other Atlassian properties; the next sign-in must round-trip the
// federated IdP. Deactivation is reversible (admins can re-enable) —
// distinct from the previous implementation which called the
// destructive DELETE /rest/api/3/user site endpoint and removed
// the user permanently.
//
// userExternalID is the Atlassian accountId (the same value
// SyncIdentities emits as Identity.ExternalID). 200 / 204 means
// propagated; 404 means the user is already gone and is treated
// as success (idempotent kill switch per the leaver contract). Any other
// status returns a non-nil err so the leaver flow logs it but
// continues to the next kill-switch layer.
func (c *JiraAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	if userExternalID == "" {
		return fmt.Errorf("jira: session revoke: userExternalID is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	fullURL := c.adminBaseURL() + "/users/" + url.PathEscape(userExternalID) + "/manage/lifecycle/disable"
	req, err := c.newRequest(ctx, secrets, http.MethodPost, fullURL)
	if err != nil {
		return err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("jira: session revoke: %w", err)
	}
	// Drain on every return path (the success cases below return without
	// reading the body) so net/http can reuse the keep-alive connection,
	// matching the provision/revoke write paths in connector.go.
	defer drainAndClose(resp)
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("jira: session revoke status %d: %s", resp.StatusCode, string(body))
}
