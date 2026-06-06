package dropbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// RevokeUserSessions implements access.SessionRevoker for Dropbox.
// It calls POST /2/team/members/revoke_device_sessions with the
// supplied team member identifier, which signs the user out of
// every linked web / desktop / mobile Dropbox session in a single
// call.
//
// userExternalID is the Dropbox team_member_id (the same value
// SyncIdentities emits as Identity.ExternalID). 200 / 204 means
// propagated; 404 / member_not_found means the user is already
// gone and is treated as success (idempotent kill switch).
// Any other status returns a non-nil err so the
// leaver flow logs it but continues to the next kill-switch
// layer.
func (c *DropboxAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	if userExternalID == "" {
		return fmt.Errorf("dropbox: session revoke: userExternalID is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload := map[string]interface{}{
		"team_member_id":   userExternalID,
		"delete_on_unlink": false,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("dropbox: session revoke: marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL()+"/2/team/members/revoke_device_sessions", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("dropbox: session revoke: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		return nil
	case http.StatusNotFound:
		return nil
	case http.StatusConflict:
		// Dropbox returns 409 with member_not_found tag for already-removed members.
		if bytes.Contains(respBody, []byte("member_not_found")) ||
			bytes.Contains(respBody, []byte("user_not_in_team")) {
			return nil
		}
	}
	return fmt.Errorf("dropbox: session revoke status %d: %s", resp.StatusCode, string(respBody))
}
