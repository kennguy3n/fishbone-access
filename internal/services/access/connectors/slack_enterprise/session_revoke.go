package slack_enterprise

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// RevokeUserSessions implements access.SessionRevoker. Slack Enterprise
// Grid exposes `admin.users.session.reset` (POST, form-encoded body
// `user=<userId>`) which logs the supplied user out of every active
// session across every workspace in the grid.
//
// Slack returns HTTP 200 even on logical errors, signalled by the
// JSON `ok` boolean. We treat `user_not_found` as idempotent success
// (the user is already gone) per the leaver contract; any
// other `ok=false` payload surfaces as an error so the JML caller can
// log and continue.
func (c *SlackEnterpriseAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	if userExternalID == "" {
		return fmt.Errorf("slack_enterprise: session revoke: userExternalID is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	form := url.Values{}
	form.Set("user", userExternalID)
	endpoint := c.baseURL() + "/api/admin.users.session.reset"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("slack_enterprise: session revoke: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusNotFound {
			return nil
		}
		return fmt.Errorf("slack_enterprise: session revoke status %d: %s", resp.StatusCode, string(body))
	}
	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("slack_enterprise: session revoke decode: %w", err)
	}
	if result.OK {
		return nil
	}
	if result.Error == "user_not_found" {
		return nil
	}
	return fmt.Errorf("slack_enterprise: session revoke: %s", result.Error)
}
