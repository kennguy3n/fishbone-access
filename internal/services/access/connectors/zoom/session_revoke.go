package zoom

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// RevokeUserSessions implements access.SessionRevoker for Zoom. It
// calls DELETE /v2/users/{userId}/token which revokes the user's
// active SSO token plus every refresh token issued to the account,
// forcing the user to re-authenticate against the federated IdP on
// the next sign-in attempt.
//
// userExternalID is the Zoom user identifier (the same value
// SyncIdentities emits as Identity.ExternalID). 204 / 200 means
// propagated; 404 means the user is already gone and is treated
// as success (idempotent kill switch per the leaver contract). Any other
// status returns a non-nil err so the leaver flow logs it but
// continues to the next kill-switch layer.
func (c *ZoomAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	if userExternalID == "" {
		return fmt.Errorf("zoom: session revoke: userExternalID is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	tok, err := c.accessToken(ctx, cfg, secrets)
	if err != nil {
		return fmt.Errorf("zoom: session revoke: %w", err)
	}
	req, err := c.newRequest(ctx, tok, http.MethodDelete, "/users/"+url.PathEscape(userExternalID)+"/token")
	if err != nil {
		return err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("zoom: session revoke: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("zoom: session revoke status %d: %s", resp.StatusCode, string(body))
}
