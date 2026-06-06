// Package gitlab — IdentityDeltaSyncer implementation.
//
// GitLab exposes user-lifecycle events through the same Group
// Audit Events API already consumed by audit.go:
//
//	GET /api/v4/groups/{group_id}/audit_events
//	    ?created_after={RFC3339}&sort=asc&per_page=100&page={n}
//
// SyncIdentitiesDelta filters the audit stream to events that
// affect group membership and surfaces them as identity batches:
//
//	user_add_to_group  / member_created     → batch{active}
//	user_access_change / member_updated     → batch{active}
//	user_remove_from_group / member_destroyed → removedExternalIDs
//
// The deltaLink we persist is the newest observed `created_at`
// (RFC3339-nano). On the next sync we feed it back as
// `created_after`. The endpoint is a strict event stream so the
// at-least-once delivery semantics inherent to second-resolution
// cursors are acceptable — the downstream identity reconciler is
// idempotent on (ExternalID, Status).
//
// 403 Forbidden / 404 Not Found (token lacks audit_events scope,
// or group is on a tier that doesn't expose audit events) collapse
// to access.ErrDeltaTokenExpired so the orchestrator falls back to
// a full SyncIdentities pass via /groups/{id}/members.
package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// SyncIdentitiesDelta walks the GitLab group audit log for
// user-lifecycle events since the supplied cursor (RFC3339-nano
// timestamp) and emits one batch per upstream page.
func (c *GitLabAccessConnector) SyncIdentitiesDelta(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	deltaLink string,
	handler func(batch []*access.Identity, removedExternalIDs []string, nextLink string) error,
) (string, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return "", err
	}
	var since time.Time
	if deltaLink != "" {
		since = parseGitlabTime(deltaLink)
	}
	if since.IsZero() {
		since = time.Now().UTC().Add(-1 * time.Hour)
	}
	cursorMax := since
	page := 1
	base := c.baseURL(cfg)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		q := url.Values{}
		q.Set("per_page", "100")
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("sort", "asc")
		q.Set("created_after", since.UTC().Format(time.RFC3339Nano))
		fullURL := fmt.Sprintf("%s/api/v4/groups/%s/audit_events?%s", base, url.PathEscape(cfg.GroupID), q.Encode())
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return "", err
		}
		resp, doErr := c.doRaw(req)
		if resp != nil && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound) {
			return "", access.ErrDeltaTokenExpired
		}
		if doErr != nil {
			return "", doErr
		}
		var events []gitlabAuditEvent
		if err := json.Unmarshal(resp.Body, &events); err != nil {
			return "", fmt.Errorf("gitlab: decode delta audit page: %w", err)
		}
		batch, removed, pageMax := mapGitlabLifecycleEvents(events, cursorMax)
		if pageMax.After(cursorMax) {
			cursorMax = pageMax
		}
		next := strings.TrimSpace(resp.Header.Get("X-Next-Page"))
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
		page++
	}
	if cursorMax.Equal(since) {
		return deltaLink, nil
	}
	return cursorMax.UTC().Format(time.RFC3339Nano), nil
}

// mapGitlabLifecycleEvents projects a slice of audit events into
// (active-batch, removed-IDs, latest-seen-timestamp). Events whose
// detail event_name (or change) does not match a recognised
// membership-affecting action are skipped silently — they belong
// to audit.go's full audit stream, not this lifecycle delta.
func mapGitlabLifecycleEvents(events []gitlabAuditEvent, cursorMax time.Time) ([]*access.Identity, []string, time.Time) {
	var batch []*access.Identity
	var removed []string
	maxTS := cursorMax
	for i := range events {
		e := &events[i]
		if e.ID == 0 {
			continue
		}
		ts := parseGitlabTime(e.CreatedAt)
		if ts.After(maxTS) {
			maxTS = ts
		}
		var d gitlabAuditDetails
		if len(e.Details) > 0 {
			_ = json.Unmarshal(e.Details, &d)
		}
		eventName := strings.ToLower(strings.TrimSpace(d.EventName))
		change := strings.ToLower(strings.TrimSpace(d.Change))
		// The target of a membership event is the affected user;
		// entity_id is the group, target_id is the user. We
		// intentionally do NOT fall back to e.AuthorID when target_id
		// is empty: on GitLab membership events author_id is the
		// admin performing the action, not the user being added or
		// removed, so substituting it would produce a wrong identity
		// row (the admin's id, marked active or removed). Audit
		// records without a populated target_id are dropped — they
		// belong to the broader audit stream in audit.go, not to the
		// lifecycle-only delta path here.
		userID := gitlabTargetIDAsString(d.TargetID)
		if userID == "" {
			continue
		}
		if isGitlabRemovalEvent(eventName, change) {
			removed = append(removed, userID)
			continue
		}
		if isGitlabAddOrUpdateEvent(eventName, change) {
			batch = append(batch, &access.Identity{
				ExternalID:  userID,
				Type:        access.IdentityTypeUser,
				DisplayName: strings.TrimSpace(d.TargetDetails),
				Status:      "active",
			})
		}
	}
	return batch, removed, maxTS
}

func isGitlabRemovalEvent(eventName, change string) bool {
	for _, s := range []string{eventName, change} {
		switch s {
		case "user_remove_from_group", "remove_user_from_group", "member_destroyed", "user_destroyed", "user_left":
			return true
		}
	}
	return false
}

func isGitlabAddOrUpdateEvent(eventName, change string) bool {
	for _, s := range []string{eventName, change} {
		switch s {
		case "user_add_to_group", "add_user_to_group", "member_created",
			"user_access_granted", "user_access_change", "member_updated",
			"change_access_level", "user_invited":
			return true
		}
	}
	return false
}

// gitlabTargetIDAsString tolerates both numeric (the modern GitLab
// audit-event detail format) and string target_id values.
func gitlabTargetIDAsString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		if t == 0 {
			return ""
		}
		return fmt.Sprintf("%d", int64(t))
	case int64:
		if t == 0 {
			return ""
		}
		return fmt.Sprintf("%d", t)
	case nil:
		return ""
	default:
		return ""
	}
}

// InitialDeltaCursor returns an RFC3339Nano "now" timestamp that
// the next SyncIdentitiesDelta will feed back as `created_after`
// so the orchestrator can enter the delta path immediately after a
// successful full SyncIdentities run. No network call — the
// orchestrator just persists this opaque cursor verbatim.
func (c *GitLabAccessConnector) InitialDeltaCursor(
	_ context.Context,
	_ map[string]interface{},
	_ map[string]interface{},
) (string, error) {
	return time.Now().UTC().Format(time.RFC3339Nano), nil
}

var _ access.IdentityDeltaSyncer = (*GitLabAccessConnector)(nil)
