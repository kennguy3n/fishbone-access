package ping_identity

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// RevokeUserSessions implements access.SessionRevoker. PingOne exposes
// DELETE /v1/environments/{envID}/users/{userID}/sessions which
// terminates every active session for the supplied user across the
// PingOne environment (web SSO, OIDC, refresh tokens).
//
// 204 / 200 are success; 404 is treated as idempotent success (the
// user is already gone) per the leaver contract. Any other
// status surfaces as an error so the JML caller can log it and
// continue.
func (c *PingIdentityAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	if userExternalID == "" {
		return fmt.Errorf("ping_identity: session revoke: userExternalID is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return fmt.Errorf("ping_identity: session revoke: %w", err)
	}
	endpoint := c.apiURL(cfg, fmt.Sprintf("/v1/environments/%s/users/%s/sessions",
		url.PathEscape(cfg.EnvironmentID), url.PathEscape(userExternalID)))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.doRaw(req)
	if err != nil {
		return fmt.Errorf("ping_identity: session revoke: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK, http.StatusAccepted, http.StatusNotFound:
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("ping_identity: session revoke status %d: %s", resp.StatusCode, string(body))
}
