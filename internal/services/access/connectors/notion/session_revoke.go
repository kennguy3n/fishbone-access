package notion

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// RevokeUserSessions implements access.SessionRevoker for Notion.
// Notion does not expose a per-user logout endpoint on the public
// v1 API; the canonical strategy is therefore to PATCH
// the user record to its deactivated state, which the workspace
// admin surface translates into an invalidation of every active
// browser / desktop / mobile session for the supplied user. The
// next sign-in must round-trip the federated IdP.
//
// userExternalID is the Notion user ID (the same value
// SyncIdentities emits as Identity.ExternalID). 200 / 204 means
// propagated; 404 / "object_not_found" means the user is already
// gone and is treated as success (idempotent kill switch per
// ). Any other status returns a non-nil err so the leaver
// flow logs it but continues to the next kill-switch layer.
func (c *NotionAccessConnector) RevokeUserSessions(ctx context.Context, _, secretsRaw map[string]interface{}, userExternalID string) error {
	if userExternalID == "" {
		return fmt.Errorf("notion: session revoke: userExternalID is required")
	}
	secrets, err := c.decodeBoth(secretsRaw)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]interface{}{
		"status": "deactivated",
	})
	if err != nil {
		return fmt.Errorf("notion: session revoke: marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch,
		c.baseURL()+"/v1/users/"+url.PathEscape(userExternalID), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Notion-Version", notionAPIVersion)
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.APIToken))
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("notion: session revoke: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	}
	if bytes.Contains(body, []byte("object_not_found")) {
		return nil
	}
	return fmt.Errorf("notion: session revoke status %d: %s", resp.StatusCode, string(body))
}
