// Package azure — SessionRevoker over Microsoft Graph.
//
// Entra ID revokes a user's refresh tokens via POST
// /users/{id}/revokeSignInSessions. Every Microsoft-managed SaaS app
// will re-prompt for SSO on the next request once the cached access
// token expires (typically within an hour). 204/200 = propagated;
// 404 = user already gone (treated as idempotent success per the
// leaver-flow contract).
package azure

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func (c *AzureAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return fmt.Errorf("azure: session revoke: userExternalID is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client := c.graphClient(ctx, cfg, secrets)
	target := c.baseURL() + "/users/" + url.PathEscape(userExternalID) + "/revokeSignInSessions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("azure: session revoke: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	return fmt.Errorf("azure: session revoke status %d: %s", resp.StatusCode, string(body))
}

var _ access.SessionRevoker = (*AzureAccessConnector)(nil)
