// Package slack — IdentityDeltaSyncer implementation.
//
// Slack exposes user lifecycle changes through the Enterprise Grid
// Audit Logs API (`GET https://api.slack.com/audit/v1/logs`). We
// poll the same endpoint already used by audit.go but with an
// `action` filter that restricts the stream to user-affecting events:
//
//	user_created           → batch{active}
//	user_reactivated       → batch{active}
//	user_role_*_granted    → batch{active} (best-effort refresh)
//	user_role_*_revoked    → batch{active} (status change, not removal)
//	user_deactivated       → removedExternalIDs
//
// The `since` cursor we persist as the deltaLink is a Unix-seconds
// timestamp (Slack's `oldest` filter is unix-seconds). On the next
// run we pass it back as `oldest`. This is at-least-once delivery —
// the downstream registry's identity reconciler is idempotent.
//
// Slack returns `not_authorized`, `team_not_eligible`, or
// `not_an_enterprise` for non-Grid workspaces; we translate those
// to ErrDeltaTokenExpired so the orchestrator falls back to a full
// SyncIdentities run (which works on any plan via users.list).
package slack

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// userLifecycleActions is the Slack audit-log action filter for
// user-affecting events. Slack supports comma-separated values for
// the `action` query parameter.
const userLifecycleActions = "user_created,user_reactivated,user_deactivated," +
	"user_role_admin_granted,user_role_admin_revoked," +
	"user_role_owner_granted,user_role_owner_revoked"

// SyncIdentitiesDelta walks Slack's Enterprise Grid audit log for
// user lifecycle events since the supplied cursor (Unix-seconds).
func (c *SlackAccessConnector) SyncIdentitiesDelta(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	deltaLink string,
	handler func(batch []*access.Identity, removedExternalIDs []string, nextLink string) error,
) (string, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return "", err
	}

	var since time.Time
	if deltaLink != "" {
		if v, err := strconv.ParseInt(strings.TrimSpace(deltaLink), 10, 64); err == nil && v > 0 {
			since = time.Unix(v, 0).UTC()
		}
	}
	if since.IsZero() {
		since = time.Now().UTC().Add(-1 * time.Hour)
	}
	cursorMax := since
	pageCursor := ""

	// Bound the pagination loop with the same guard as the audit fetch
	// (both poll /audit/v1/logs as background jobs): a never-empty
	// next_cursor (API bug/change) must not drive unbounded HTTP
	// requests. When the budget is exhausted we fall through and persist
	// the latest cursor so the next run resumes where this one left off.
	for pageNum := 0; pageNum < slackAuditMaxPages; pageNum++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		q := url.Values{}
		q.Set("limit", "200")
		q.Set("action", userLifecycleActions)
		q.Set("oldest", fmt.Sprintf("%d", since.Unix()))
		if pageCursor != "" {
			q.Set("cursor", pageCursor)
		}
		endpoint := c.auditURL("/audit/v1/logs?" + q.Encode())
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.BotToken))
		body, apiErr, err := c.doWithAPIError(req)
		if err != nil {
			return "", err
		}
		if apiErr != "" {
			switch apiErr {
			case "not_authorized", "team_not_eligible", "not_an_enterprise":
				return "", access.ErrDeltaTokenExpired
			default:
				return "", fmt.Errorf("slack: delta audit logs: api error: %s", apiErr)
			}
		}
		var page slackAuditPage
		if err := json.Unmarshal(body, &page); err != nil {
			return "", fmt.Errorf("slack: decode delta audit page: %w", err)
		}
		batch, removed, pageMax := mapSlackLifecycleEvents(&page, cursorMax)
		if pageMax.After(cursorMax) {
			cursorMax = pageMax
		}
		next := strings.TrimSpace(page.ResponseMetadata.NextCursor)
		nextLink := ""
		if next != "" {
			nextLink = next
		}
		if err := handler(batch, removed, nextLink); err != nil {
			return "", err
		}
		if next == "" {
			break
		}
		pageCursor = next
	}
	if cursorMax.Equal(since) {
		return deltaLink, nil
	}
	return strconv.FormatInt(cursorMax.Unix(), 10), nil
}

// mapSlackLifecycleEvents projects Slack audit-log entries into
// (active-batch, removed-IDs, latest-seen-timestamp). Events whose
// target is not a user (or whose user ID is empty) are skipped.
func mapSlackLifecycleEvents(page *slackAuditPage, cursorMax time.Time) ([]*access.Identity, []string, time.Time) {
	var batch []*access.Identity
	var removed []string
	maxTS := cursorMax
	for i := range page.Entries {
		e := &page.Entries[i]
		userID := strings.TrimSpace(e.Entity.User.ID)
		if userID == "" {
			continue
		}
		ts := time.Unix(e.DateCreate, 0).UTC()
		if ts.After(maxTS) {
			maxTS = ts
		}
		switch e.Action {
		case "user_deactivated":
			removed = append(removed, userID)
		case "user_created", "user_reactivated",
			"user_role_admin_granted", "user_role_admin_revoked",
			"user_role_owner_granted", "user_role_owner_revoked":
			batch = append(batch, &access.Identity{
				ExternalID:  userID,
				Type:        access.IdentityTypeUser,
				DisplayName: userID,
				Status:      "active",
			})
		}
	}
	return batch, removed, maxTS
}

// InitialDeltaCursor returns a Unix-seconds "now" timestamp the
// orchestrator persists as the baseline cursor after a successful
// full sync. The next SyncIdentitiesDelta passes it back as Slack's
// `oldest` audit-log filter, which is itself Unix-seconds. No
// network call.
func (c *SlackAccessConnector) InitialDeltaCursor(
	_ context.Context,
	_ map[string]interface{},
	_ map[string]interface{},
) (string, error) {
	return strconv.FormatInt(time.Now().UTC().Unix(), 10), nil
}

var _ access.IdentityDeltaSyncer = (*SlackAccessConnector)(nil)
