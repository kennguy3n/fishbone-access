package google_workspace

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// RevokeUserSessions implements access.SessionRevoker for Google
// Workspace. It calls POST /admin/directory/v1/users/{userKey}/signOut
// which invalidates every active web session, refresh token, and
// OAuth-issued access token for the supplied user.
//
// userExternalID is the SyncIdentities-emitted external_id for this
// connector, which is the immutable numeric Google user id (see
// mapDirectoryUsers: ExternalID = directoryUser.ID). The Admin SDK
// accepts either the numeric id or the primary email as the {userKey}
// path segment, so callers may also pass an email, but the canonical
// key flowing through the leaver pipeline is the numeric id. A 200 /
// 204 from Google means "sign-out propagated"; a 404 means the
// user is already gone and is treated as success (idempotent kill
// switch per the leaver contract). Any other status returns a non-nil err so
// the leaver flow logs it but continues to the next layer.
func (c *GoogleWorkspaceAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	if userExternalID == "" {
		return fmt.Errorf("google_workspace: session revoke: userExternalID is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client, err := c.directoryClient(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		directoryBaseURL+"/users/"+url.PathEscape(userExternalID)+"/signOut", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("google_workspace: session revoke: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("google_workspace: session revoke status %d: %s", resp.StatusCode, string(body))
}
