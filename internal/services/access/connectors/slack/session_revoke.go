package slack

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// RevokeUserSessions implements access.SessionRevoker for Slack.
// It calls /api/admin.users.session.reset which terminates every
// active workspace and mobile session for the supplied user,
// forcing them to re-authenticate against the IdP.
//
// This endpoint requires an admin or enterprise-admin token; on a
// workspace where the bot token does not have admin scope Slack
// responds ok=false with error="not_authed" or
// "missing_scope". Both surface as non-nil err so the leaver flow
// logs them but continues to the next layer.
//
// userExternalID is the Slack user ID (the SyncIdentities-emitted
// external_id). An ok=true Slack response means propagated;
// "user_not_found" is treated as idempotent success.
func (c *SlackAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	if userExternalID == "" {
		return fmt.Errorf("slack: session revoke: userExternalID is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	form := fmt.Sprintf("user_id=%s&mobile_only=false&web_only=false", userExternalID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL()+"/admin.users.session.reset", strings.NewReader(form))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.BotToken))
	_, apiErr, err := c.doWithAPIError(req)
	if err != nil {
		return fmt.Errorf("slack: session revoke: %w", err)
	}
	if apiErr == "" || apiErr == "user_not_found" {
		return nil
	}
	return fmt.Errorf("slack: session revoke api error: %s", apiErr)
}
