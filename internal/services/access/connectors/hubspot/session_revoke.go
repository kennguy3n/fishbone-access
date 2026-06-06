package hubspot

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// RevokeUserSessions implements access.SessionRevoker for HubSpot.
// It calls DELETE /settings/v3/users/{userId} which deactivates the
// HubSpot user record; HubSpot invalidates every active web session
// and refresh token issued to that user as part of the deactivation
// side-effect, forcing the next sign-in to round-trip the IdP.
//
// userExternalID is the HubSpot user identifier (the same value
// SyncIdentities emits as Identity.ExternalID). 200 / 204 means
// propagated; 404 means the user is already gone and is treated
// as success (idempotent kill switch per the leaver contract). Any other
// status returns a non-nil err so the leaver flow logs it but
// continues to the next kill-switch layer.
func (c *HubSpotAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	if userExternalID == "" {
		return fmt.Errorf("hubspot: session revoke: userExternalID is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, "/settings/v3/users/"+url.PathEscape(userExternalID))
	if err != nil {
		return err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("hubspot: session revoke: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("hubspot: session revoke status %d: %s", resp.StatusCode, string(body))
}
