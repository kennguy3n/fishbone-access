package box

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// RevokeUserSessions implements access.SessionRevoker. Box exposes
// DELETE /2.0/users/{id}/sessions which terminates every active
// session for the supplied managed user (enterprise admin-level
// kill switch).
//
// 204 / 200 are success; 404 means the user is already gone and is
// treated as success (idempotent kill switch per the leaver contract). Any
// other status surfaces as an error so the JML caller can log it
// and continue the leaver flow.
func (c *BoxAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	if userExternalID == "" {
		return fmt.Errorf("box: session revoke: userExternalID is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := c.baseURL() + "/2.0/users/" + url.PathEscape(userExternalID) + "/sessions"
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, endpoint)
	if err != nil {
		return err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return fmt.Errorf("box: session revoke: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK, http.StatusAccepted, http.StatusNotFound:
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("box: session revoke status %d: %s", resp.StatusCode, string(body))
}
