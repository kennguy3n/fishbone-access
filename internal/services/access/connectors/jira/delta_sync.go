// Package jira — IdentityDeltaSyncer via Atlassian Admin org events.
//
// Atlassian Cloud (Jira / Confluence / org-level user management)
// exposes user lifecycle events through the Atlassian Admin REST
// API:
//
//   GET /admin/v1/orgs/{org_id}/events?from={RFC3339}
//
// The events stream is unified across all Atlassian products under
// the org. We filter to user-lifecycle event actions only and emit
// one Identity per relevant event. The persisted cursor is the most
// recent event timestamp formatted as RFC3339Nano so sub-second
// precision round-trips cleanly across save/load — matching
// gitlab/delta_sync.go:109's cross-connector cursor-precision
// contract. The wire `from=` query is formatted as RFC3339 (second
// precision) because the Atlassian Admin API filter only honors
// second granularity; events at the cursor's whole-second boundary
// may therefore re-deliver, but the downstream identity reconciler
// is idempotent on (ExternalID, Status) so the at-least-once
// semantic is safe.
//
// User-lifecycle actions we surface (kept in sync with the switch in
// mapJiraUserLifecycleEvent below):
//
//	user_created                       -> active
//	user_invited                       -> active (invited state still
//	                                      counts as active for access
//	                                      reconciliation; the full sync
//	                                      will correct status if needed)
//	user_invitation_accepted           -> active
//	user_activated                     -> active
//	user_email_changed                 -> active (email-update event)
//	user_deactivated                   -> inactive
//	user_suspended                     -> inactive
//	user_deleted                       -> removed (tombstoned)
//	user_removed                       -> removed (tombstoned)
//
// 401/403/404 collapse to access.ErrDeltaTokenExpired so the
// registry falls back to a full re-enumeration — this matches the
// audit code's soft-skip and what the optional_interfaces.go
// contract requires for cursor-rejection. Any other non-2xx is a
// hard error so the worker can retry.
package jira

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// SyncIdentitiesDelta walks /admin/v1/orgs/{org_id}/events from the
// supplied cursor, emitting one Identity per user-lifecycle event.
// The returned finalDeltaLink is an RFC3339Nano timestamp the caller
// stores and feeds back on the next sync. RFC3339Nano preserves
// sub-second precision across save/load; the wire `from=` filter
// uses RFC3339 second-precision because Atlassian's endpoint only
// honors that. See package comment for the at-least-once delivery
// rationale.
func (c *JiraAccessConnector) SyncIdentitiesDelta(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	deltaLink string,
	handler func(batch []*access.Identity, removedExternalIDs []string, nextLink string) error,
) (string, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return "", err
	}
	orgID := ""
	if configRaw != nil {
		if v, ok := configRaw["org_id"].(string); ok {
			orgID = strings.TrimSpace(v)
		}
	}
	if orgID == "" {
		return "", errors.New("jira: delta sync: config.org_id is required")
	}
	var since time.Time
	if s := strings.TrimSpace(deltaLink); s != "" {
		// Try RFC3339Nano first to match parseJiraTime in
		// audit.go — keeps in-package parsing-order conventions
		// consistent. Either order is correct (Go's time.Parse
		// with RFC3339Nano transparently accepts whole-second
		// inputs) so this is purely a readability fix.
		if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
			since = ts.UTC()
		} else if ts, err := time.Parse(time.RFC3339, s); err == nil {
			since = ts.UTC()
		} else {
			return "", access.ErrDeltaTokenExpired
		}
	}
	if since.IsZero() {
		since = time.Now().UTC().Add(-1 * time.Hour)
	}

	q := url.Values{}
	// Wire filter uses RFC3339 because Atlassian's `from=` only
	// honors second precision. Persisted cursor below uses
	// RFC3339Nano so save/load preserves sub-second event ordering.
	q.Set("from", since.UTC().Format(time.RFC3339))
	nextURL := c.adminBaseURL() + "/admin/v1/orgs/" + url.PathEscape(orgID) + "/events?" + q.Encode()

	newestSeen := since
	for nextURL != "" {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return "", err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return "", fmt.Errorf("jira: delta events: %w", err)
		}
		body, readErr := readLimited(resp)
		if readErr != nil {
			// A truncated body would JSON-unmarshal into a partial
			// page and the cursor would advance past events we
			// never saw. Surface the read failure so the worker
			// retries instead of silently moving forward.
			return "", readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return "", access.ErrDeltaTokenExpired
		case http.StatusBadRequest:
			return "", access.ErrDeltaTokenExpired
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return "", fmt.Errorf("jira: delta events status %d: %s", resp.StatusCode, string(body))
		}
		var page jiraAuditPage
		if err := json.Unmarshal(body, &page); err != nil {
			return "", fmt.Errorf("jira: decode delta page: %w", err)
		}

		batch := make([]*access.Identity, 0, len(page.Data))
		var removed []string
		for i := range page.Data {
			ev := &page.Data[i]
			// Advance the cursor for every event on the page, not
			// just the user-lifecycle ones we surface to the
			// handler. The Atlassian Admin events stream is
			// unified across all products and event categories
			// (project / permission / settings changes outnumber
			// user changes on most orgs); if we only advanced on
			// lifecycle events the cursor would pin behind every
			// unrelated event and each subsequent sync would
			// re-fetch the same already-skipped pages. Matches
			// gitlab/delta_sync.go's maxTS update pattern.
			ts := parseJiraTime(ev.Attributes.Time)
			if ts.After(newestSeen) {
				newestSeen = ts
			}
			id, status, ok := mapJiraUserLifecycleEvent(ev)
			if !ok {
				continue
			}
			if status == "removed" {
				removed = append(removed, id.ExternalID)
				continue
			}
			batch = append(batch, id)
		}

		next := strings.TrimSpace(page.Links.Next)
		// Rewrite absolute next links to the urlOverride for tests.
		if c.urlOverride != "" && strings.HasPrefix(next, "https://api.atlassian.com") {
			next = strings.Replace(next, "https://api.atlassian.com", strings.TrimRight(c.urlOverride, "/"), 1)
		}
		if err := handler(batch, removed, next); err != nil {
			return "", err
		}
		if next == "" {
			break
		}
		nextURL = next
	}
	// RFC3339Nano preserves sub-second precision across
	// save/load (the orchestrator persists this string and feeds
	// it back on the next sync). Matches gitlab/delta_sync.go:109
	// nano-precision cursor contract.
	return newestSeen.UTC().Format(time.RFC3339Nano), nil
}

// mapJiraUserLifecycleEvent returns an Identity + lifecycle status
// for user events the registry cares about, or ok=false for events
// the registry should ignore. The Atlassian Admin API uses
// `user_*` event action names; we match a documented subset.
//
// Status values:
//
//	"active"   -> identity is currently active
//	"inactive" -> identity has been deactivated (still exists, not
//	              listed as removed because the user record itself
//	              persists in Atlassian)
//	"removed"  -> identity should be tombstoned (deleted from the org)
func mapJiraUserLifecycleEvent(e *jiraAuditEvent) (*access.Identity, string, bool) {
	if e == nil {
		return nil, "", false
	}
	action := strings.TrimSpace(strings.ToLower(e.Attributes.Action))
	var status string
	switch action {
	case "user_created",
		"user_invited",
		"user_invitation_accepted",
		"user_activated",
		"user_email_changed":
		status = "active"
	case "user_deactivated", "user_suspended":
		status = "inactive"
	case "user_deleted", "user_removed":
		status = "removed"
	default:
		return nil, "", false
	}

	// Atlassian encodes the target user as the first context
	// entry of type "USER". We never fall back to actor.ID — for
	// admin-initiated events (user_invited / user_deactivated /
	// user_suspended / user_deleted / user_removed) the actor is
	// the admin performing the action, NOT the user being acted
	// on. A silent fallback would mis-attribute the lifecycle
	// status to the admin's identity record (e.g. marking the
	// admin "inactive" when they suspended someone else, or
	// tombstoning the admin when they deleted someone else).
	// This matches the cross-connector contract: every other
	// IdentityDeltaSyncer in the repo (gitlab/delta_sync.go:139-148,
	// aws/delta_sync.go:277-321, slack/delta_sync.go:136-138)
	// drops events without a target_id rather than falling back
	// to the API caller. The next full sync will reconcile any
	// dropped events idempotently.
	targetID := ""
	targetEmail := ""
	targetDisplayName := ""
	targetType := access.IdentityTypeUser
	for _, ctxEntry := range e.Attributes.Context {
		// strings.EqualFold is already case-insensitive — one check
		// handles "USER", "user", "User", etc.
		if strings.EqualFold(ctxEntry.Type, "USER") {
			targetID = strings.TrimSpace(ctxEntry.ID)
			if email, ok := ctxEntry.Attributes["email"].(string); ok {
				targetEmail = strings.TrimSpace(email)
			}
			// Atlassian Admin event payloads frequently surface the
			// target user's display name under either "displayName"
			// (the modern key, matching connector.go's full-sync
			// shape) or "name" (the legacy key still seen on some
			// product event categories). Prefer the modern key.
			// Populating DisplayName here closes the gap between
			// delta-discovered identities (previously blank) and
			// full-sync-discovered identities (always populated) so
			// the UI / audit pipeline doesn't show empty names
			// between a delta and the next full sync.
			if dn, ok := ctxEntry.Attributes["displayName"].(string); ok {
				targetDisplayName = strings.TrimSpace(dn)
			}
			if targetDisplayName == "" {
				if name, ok := ctxEntry.Attributes["name"].(string); ok {
					targetDisplayName = strings.TrimSpace(name)
				}
			}
			// Mirror the IdentityTypeServiceAccount mapping the
			// full sync applies at connector.go:258-261. The
			// Admin events payload occasionally includes
			// accountType in the USER context attributes (the
			// product surface is undocumented but observed for
			// app-triggered lifecycle events). When present, use
			// it so service-account creations / deactivations
			// don't appear as regular users until the next full
			// sync. When absent, leave the default IdentityTypeUser
			// — the full sync is idempotent and will correct it.
			if at, ok := ctxEntry.Attributes["accountType"].(string); ok {
				if strings.EqualFold(strings.TrimSpace(at), "app") {
					targetType = access.IdentityTypeServiceAccount
				}
			}
			break
		}
	}
	if targetID == "" {
		// Drop the event entirely when the USER context entry is
		// missing — no actor fallback. See the rationale block
		// above the for-loop.
		return nil, "", false
	}

	id := &access.Identity{
		ExternalID:  targetID,
		Type:        targetType,
		DisplayName: targetDisplayName,
		Email:       targetEmail,
		Status:      status,
	}
	return id, status, true
}

// InitialDeltaCursor returns an RFC3339Nano "now" timestamp the
// orchestrator persists as the baseline cursor after a successful
// full sync, so the very next run enters the delta path. The Jira
// SyncIdentitiesDelta accepts RFC3339 or RFC3339Nano on the cursor
// (parseJiraTime tries both) and re-emits RFC3339Nano. No network
// call.
func (c *JiraAccessConnector) InitialDeltaCursor(
	_ context.Context,
	_ map[string]interface{},
	_ map[string]interface{},
) (string, error) {
	return time.Now().UTC().Format(time.RFC3339Nano), nil
}

var _ access.IdentityDeltaSyncer = (*JiraAccessConnector)(nil)
