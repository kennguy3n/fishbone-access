package microsoft

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// RevokeUserSessions implements access.SessionRevoker for
// Microsoft Entra ID. It calls POST /users/{id}/revokeSignInSessions
// which invalidates every refresh token issued to the supplied
// user, forcing every Microsoft-managed SaaS app to re-authenticate
// against the IdP on the next request.
//
// userExternalID is the Entra user object id (the SyncIdentities-
// emitted external_id). 204 / 200 from Graph means propagated;
// 404 means the user is already gone and is treated as success
// (idempotent kill switch per the leaver contract). Any other status returns
// a non-nil err so the leaver flow logs it but continues to the
// next layer.
func (c *M365AccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	if userExternalID == "" {
		return fmt.Errorf("microsoft: session revoke: userExternalID is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client := c.graphClient(ctx, cfg, secrets)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		graphBaseURL+"/users/"+url.PathEscape(userExternalID)+"/revokeSignInSessions", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("microsoft: session revoke: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("microsoft: session revoke status %d: %s", resp.StatusCode, string(body))
}
