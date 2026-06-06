// Package zendesk — IdentityDeltaSyncer via /api/v2/audit_logs.
//
// Zendesk exposes user lifecycle events through the same audit log
// endpoint the access-audit pipeline already uses:
//
//	GET /api/v2/audit_logs.json
//	    ?filter[created_at][]={since}&filter[created_at][]={now}
//	    &sort_by=created_at&sort_order=asc
//
// Each `audit_logs[]` entry carries:
//
//	source_type   ("user" for user lifecycle events)
//	action        ("create" / "update" / "destroy" / "soft_destroy" / ...)
//	source_id     (the user id when source_type == "user")
//	created_at    (RFC3339 timestamp)
//
// User lifecycle action mapping:
//
//	action=create                     -> active
//	action=update                     -> active (full sync corrects status)
//	action=destroy / soft_destroy     -> removed (tombstoned)
//
// Status-code mapping:
//
//	400 invalid cursor / filter      -> ErrDeltaTokenExpired (clear cursor,
//	                                    fall back to full sync)
//	401 unauthorized                 -> hard error (credentials issue;
//	                                    preserve the cursor so the next
//	                                    successful run resumes where it
//	                                    left off rather than re-enumerating
//	                                    everything after credential rot)
//	403 plan tier gating             -> ErrDeltaTokenExpired (audit logs
//	                                    are a Suite Professional+ feature;
//	                                    full sync is the correct fallback)
//	404 endpoint gone                -> ErrDeltaTokenExpired
//	other non-2xx                    -> hard error so the worker can retry
package zendesk

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

// SyncIdentitiesDelta walks /api/v2/audit_logs.json from the supplied
// cursor, emitting one Identity per user-lifecycle audit event. The
// returned finalDeltaLink is the most recent event timestamp formatted
// as RFC3339Nano so any sub-second precision the caller fed in via
// deltaLink round-trips symmetrically. At-least-once delivery applies
// for same-second events — the downstream reconciler is idempotent.
func (c *ZendeskAccessConnector) SyncIdentitiesDelta(
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
	if s := strings.TrimSpace(deltaLink); s != "" {
		if ts, perr := time.Parse(time.RFC3339Nano, s); perr == nil {
			since = ts.UTC()
		} else if ts, perr := time.Parse(time.RFC3339, s); perr == nil {
			since = ts.UTC()
		} else {
			return "", access.ErrDeltaTokenExpired
		}
	}
	if since.IsZero() {
		since = time.Now().UTC().Add(-1 * time.Hour)
	}

	q := url.Values{}
	q.Set("sort_by", "created_at")
	q.Set("sort_order", "asc")
	// Server-side filter to user-lifecycle events only. The mapping
	// function still gates on source_type for defence-in-depth in
	// case Zendesk ever returns mixed records, but pushing the
	// filter into the query keeps payload size + page count
	// proportional to user-change volume rather than total audit
	// volume on large workspaces.
	q.Set("filter[source_type]", "user")
	q.Add("filter[created_at][]", since.UTC().Format(time.RFC3339))
	// Upper bound matches audit.go's `time.Now().UTC()` pattern. We
	// previously used now+24h as a clock-skew guard, but Zendesk
	// stamps `created_at` from its own server clock so future-dated
	// events never appear in the response; the 24h cushion was
	// unjustified and diverged from the audit-fetch path. Keeping
	// the two paths aligned simplifies reasoning about which events
	// each can return for a given window.
	q.Add("filter[created_at][]", time.Now().UTC().Format(time.RFC3339))
	nextURL := c.baseURL(cfg) + "/api/v2/audit_logs.json?" + q.Encode()

	newestSeen := since
	for nextURL != "" {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return "", err
		}
		// httpStatus (outer scope) is the upstream HTTP status code
		// for branching on auth / tier-gating semantics; the inner
		// loop's `status` is the lifecycle-status string (active /
		// removed) returned by the event mapper. Naming the outer
		// one explicitly removes the shadowing warning the linter
		// (and a reader) would otherwise have to reason through.
		body, httpStatus, err := c.doWithStatus(req)
		if err != nil {
			switch httpStatus {
			case http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound:
				// 400 -> stored cursor / filter is unparseable.
				// 403 -> plan tier doesn't ship audit logs (Suite
				//        Professional+); a full sync is the correct
				//        fallback rather than persistently re-asking.
				// 404 -> endpoint moved / not enabled.
				return "", access.ErrDeltaTokenExpired
			}
			// Everything else — including 401 (credentials issue) and
			// 5xx — surfaces as a hard error so the worker retries.
			// On 401 we intentionally do *not* return
			// ErrDeltaTokenExpired: clearing the cursor on credential
			// rot would silently discard incremental progress, since
			// the follow-up full sync would also fail with 401 and
			// after credentials are fixed we'd have nothing to resume
			// from.
			return "", err
		}
		var page zendeskAuditPage
		if err := json.Unmarshal(body, &page); err != nil {
			return "", fmt.Errorf("zendesk: decode delta page: %w", err)
		}

		batch := make([]*access.Identity, 0, len(page.AuditLogs))
		var removed []string
		for i := range page.AuditLogs {
			e := &page.AuditLogs[i]
			id, status, ok := mapZendeskUserLifecycleEvent(e)
			if !ok {
				continue
			}
			ts := parseZendeskTime(e.CreatedAt)
			if ts.After(newestSeen) {
				newestSeen = ts
			}
			if status == "removed" {
				removed = append(removed, id.ExternalID)
				continue
			}
			batch = append(batch, id)
		}

		next := strings.TrimSpace(page.NextPage)
		if c.urlOverride != "" && next != "" {
			next = strings.Replace(next, "https://"+cfg.Subdomain+".zendesk.com", strings.TrimRight(c.urlOverride, "/"), 1)
		}
		if err := handler(batch, removed, next); err != nil {
			return "", err
		}
		if next == "" {
			break
		}
		nextURL = next
	}
	// Return the cursor in RFC3339Nano so any sub-second precision
	// the caller fed in via deltaLink round-trips through this sync.
	// audit_logs created_at is RFC3339 second precision in practice,
	// but using Nano here makes the input/output formats symmetrical.
	return newestSeen.UTC().Format(time.RFC3339Nano), nil
}

// mapZendeskUserLifecycleEvent returns an Identity + lifecycle
// status for user audit events the registry cares about, or
// ok=false for unrelated events (ticket changes, group changes,
// admin role changes, etc.).
func mapZendeskUserLifecycleEvent(e *zendeskAuditLog) (*access.Identity, string, bool) {
	if e == nil || e.ID == 0 {
		return nil, "", false
	}
	if !strings.EqualFold(e.SourceType, "user") {
		return nil, "", false
	}
	if e.SourceID == 0 {
		return nil, "", false
	}
	externalID := fmt.Sprintf("%d", e.SourceID)
	action := strings.TrimSpace(strings.ToLower(e.Action))
	switch action {
	case "create":
		return &access.Identity{
			ExternalID:  externalID,
			Type:        access.IdentityTypeUser,
			DisplayName: strings.TrimSpace(e.SourceLabel),
			Status:      "active",
		}, "active", true
	case "update":
		return &access.Identity{
			ExternalID:  externalID,
			Type:        access.IdentityTypeUser,
			DisplayName: strings.TrimSpace(e.SourceLabel),
			Status:      "active",
		}, "active", true
	case "destroy", "soft_destroy", "delete":
		return &access.Identity{ExternalID: externalID, Type: access.IdentityTypeUser}, "removed", true
	default:
		return nil, "", false
	}
}

// parseZendeskTime is a small helper that mirrors the existing audit
// code; kept colocated so delta_sync.go stays self-contained.
func parseZendeskTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts
	}
	return time.Time{}
}

// InitialDeltaCursor returns an RFC3339Nano "now" timestamp the
// orchestrator persists as the baseline cursor after a successful
// full sync, so the very next run enters the delta path.
// SyncIdentitiesDelta downgrades to RFC3339-second precision on the
// wire (Zendesk's filter API only accepts second-resolution); the
// nanosecond fidelity matters only for the round-trip identity of
// the cursor itself. No network call.
func (c *ZendeskAccessConnector) InitialDeltaCursor(
	_ context.Context,
	_ map[string]interface{},
	_ map[string]interface{},
) (string, error) {
	return time.Now().UTC().Format(time.RFC3339Nano), nil
}

var _ access.IdentityDeltaSyncer = (*ZendeskAccessConnector)(nil)
