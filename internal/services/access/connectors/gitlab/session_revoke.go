package gitlab

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// RevokeUserSessions implements access.SessionRevoker. GitLab does not
// expose a single "kill every session for user X" endpoint; the
// closest admin-level mechanism is to revoke the user's personal
// access tokens via DELETE /api/v4/personal_access_tokens?user_id=...
// (effectively logging the user out of API surfaces and removing
// long-lived OAuth tokens). The leaver flow then relies on SSO
// removal to terminate web sessions.
//
// 204 / 200 are success; 404 is treated as idempotent success (the
// user is already gone); other statuses surface as errors so the
// JML caller can log and continue.
func (c *GitLabAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	if userExternalID == "" {
		return fmt.Errorf("gitlab: session revoke: userExternalID is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	q := url.Values{}
	q.Set("user_id", userExternalID)
	endpoint := c.baseURL(cfg) + "/api/v4/personal_access_tokens?" + q.Encode()
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, endpoint)
	if err != nil {
		return err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("gitlab: session revoke: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK, http.StatusAccepted, http.StatusNotFound:
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("gitlab: session revoke status %d: %s", resp.StatusCode, string(body))
}
