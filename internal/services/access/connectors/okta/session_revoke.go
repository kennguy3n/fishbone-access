package okta

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// RevokeUserSessions implements access.SessionRevoker. It calls
// DELETE /api/v1/users/{userId}/sessions which terminates every
// active session for the supplied user across all Okta-managed
// surfaces (web, OIDC, OAuth refresh tokens).
//
// The endpoint returns 204 on success; 404 means the user is
// already gone and is treated as success (idempotent kill switch
// per the leaver contract). Any other status is a non-nil error — callers
// log it but do not abort the leaver flow.
func (c *OktaAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	if userExternalID == "" {
		return fmt.Errorf("okta: session revoke: userExternalID is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/api/v1/users/%s/sessions", url.PathEscape(userExternalID))
	req, err := c.newRequest(ctx, cfg, secrets, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return fmt.Errorf("okta: session revoke: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK, http.StatusNotFound:
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("okta: session revoke status %d: %s", resp.StatusCode, string(body))
}
