package zendesk

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// RevokeUserSessions implements access.SessionRevoker for Zendesk.
// It calls DELETE /api/v2/users/{id}/sessions.json which terminates
// every active session token issued to the supplied user. The
// next API or web call requires a fresh sign-in through the
// federated IdP.
//
// userExternalID is the numeric Zendesk user identifier (the same
// value SyncIdentities emits as Identity.ExternalID). 200 / 204
// means propagated; 404 means the user is already gone and is
// treated as success (idempotent kill switch per the leaver contract). Any
// other status returns a non-nil err so the leaver flow logs it
// but continues to the next kill-switch layer.
func (c *ZendeskAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	if userExternalID == "" {
		return fmt.Errorf("zendesk: session revoke: userExternalID is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	fullURL := c.baseURL(cfg) + "/api/v2/users/" + url.PathEscape(userExternalID) + "/sessions.json"
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, fullURL)
	if err != nil {
		return err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("zendesk: session revoke: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("zendesk: session revoke status %d: %s", resp.StatusCode, string(body))
}
