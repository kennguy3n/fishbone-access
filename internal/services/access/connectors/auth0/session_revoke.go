package auth0

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// RevokeUserSessions implements access.SessionRevoker for Auth0.
// It calls DELETE /api/v2/users/{userId}/sessions which invalidates
// every active session and refresh token issued to the supplied
// user, forcing them to re-authenticate against the IdP.
//
// userExternalID is the Auth0 user_id (the SyncIdentities-emitted
// external_id, e.g. "auth0|abc123"). 200 / 204 means propagated;
// 404 means the user is already gone and is treated as success
// (idempotent kill switch per the leaver contract). Any other status returns
// a non-nil err so the leaver flow logs it but continues to the
// next layer.
func (c *Auth0AccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	if userExternalID == "" {
		return fmt.Errorf("auth0: session revoke: userExternalID is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	req, err := c.newAuthedRequest(ctx, cfg, token, http.MethodDelete,
		"/api/v2/users/"+url.PathEscape(userExternalID)+"/sessions", nil)
	if err != nil {
		return err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return fmt.Errorf("auth0: session revoke: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	}
	return fmt.Errorf("auth0: session revoke status %d", resp.StatusCode)
}
