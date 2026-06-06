// Package datadog — IdentityDeltaSyncer implementation backed by the
// Audit Trail API.
//
// Datadog exposes audit events at GET /api/v2/audit/events. The
// delta sync filters to user-lifecycle events (User created, User
// updated, User disabled) and feeds each page through the supplied
// handler. The cursor stored between runs is the RFC3339 timestamp
// of the newest event seen — Datadog retains audit events for 30
// days, so a cursor older than that triggers
// access.ErrDeltaTokenExpired and the caller falls back to a full
// SyncIdentities enumeration.
package datadog

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

// datadogAuditRetention is the upstream's documented retention
// window for audit events. A cursor older than this is rejected
// with HTTP 400 / 422 (Datadog's behaviour); we treat that signal
// as ErrDeltaTokenExpired and the orchestrator falls back to a
// full sync.
const datadogAuditRetention = 30 * 24 * time.Hour

// SyncIdentitiesDelta walks the audit-events stream, emitting one
// batch per page in chronological order.
func (c *DatadogAccessConnector) SyncIdentitiesDelta(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	deltaLink string,
	handler func(batch []*access.Identity, removedExternalIDs []string, nextLink string) error,
) (string, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return "", err
	}

	// Snapshot the wall clock once so the query window is internally
	// consistent: filter[to] is this instant and (on a first run)
	// filter[from] is exactly one hour earlier. Reading time.Now()
	// separately for the lower and upper bound left a window where an
	// event arriving between the two reads could fall outside both the
	// current and the next poll.
	now := time.Now().UTC()

	var since time.Time
	if strings.TrimSpace(deltaLink) != "" {
		parsed, perr := time.Parse(time.RFC3339, strings.TrimSpace(deltaLink))
		if perr != nil {
			return "", fmt.Errorf("datadog: invalid deltaLink cursor %q: %w", deltaLink, perr)
		}
		if now.Sub(parsed) > datadogAuditRetention {
			return "", access.ErrDeltaTokenExpired
		}
		since = parsed
	} else {
		// First run — pull the last hour so the initial batch is bounded.
		since = now.Add(-1 * time.Hour)
	}

	base := c.baseURL(cfg)
	q := url.Values{}
	q.Set("page[limit]", "100")
	q.Set("sort", "timestamp")
	q.Set("filter[query]",
		"@evt.name:(\"User created\" OR \"User updated\" OR \"User disabled\" OR \"User invited\" OR \"User deleted\")")
	q.Set("filter[from]", since.UTC().Format(time.RFC3339))
	q.Set("filter[to]", now.Format(time.RFC3339))

	requestURL := base + "/api/v2/audit/events?" + q.Encode()
	newestSeen := since
	for requestURL != "" {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, requestURL)
		if err != nil {
			return "", err
		}
		body, err := c.do(req)
		if err != nil {
			// Datadog returns 400 / 422 with an `errors` array
			// referencing "retention" / "out of range" when the cursor
			// is too old. We inspect the typed httpError from do() so
			// the detection is decoupled from the formatted error
			// string — future refactors of do()'s format string won't
			// silently break the fallback-to-full-sync mechanism.
			var httpErr *httpError
			if errors.As(err, &httpErr) && isDatadogCursorExpired(httpErr) {
				return "", access.ErrDeltaTokenExpired
			}
			return "", err
		}
		var page ddDeltaPage
		if err := json.Unmarshal(body, &page); err != nil {
			return "", fmt.Errorf("datadog: decode audit page: %w", err)
		}
		batch := make([]*access.Identity, 0, len(page.Data))
		removed := make([]string, 0)
		for _, ev := range page.Data {
			ts, _ := time.Parse(time.RFC3339Nano, ev.Attributes.Timestamp)
			if ts.IsZero() {
				ts, _ = time.Parse(time.RFC3339, ev.Attributes.Timestamp)
			}
			if ts.After(newestSeen) {
				newestSeen = ts
			}
			userID, _ := ev.Attributes.Attrs["usr.id"].(string)
			email, _ := ev.Attributes.Attrs["usr.email"].(string)
			name, _ := ev.Attributes.Attrs["usr.name"].(string)
			evtName, _ := ev.Attributes.Attrs["evt.name"].(string)
			if userID == "" {
				continue
			}
			switch evtName {
			case "User deleted", "User disabled":
				removed = append(removed, userID)
			default:
				display := name
				if display == "" {
					display = email
				}
				batch = append(batch, &access.Identity{
					ExternalID:  userID,
					Type:        access.IdentityTypeUser,
					DisplayName: display,
					Email:       email,
					Status:      "active",
				})
			}
		}
		nextLink := strings.TrimSpace(page.Links.Next)
		if c.urlOverride != "" && strings.HasPrefix(nextLink, "https://") {
			if idx := strings.Index(nextLink[len("https://"):], "/"); idx != -1 {
				nextLink = strings.TrimRight(c.urlOverride, "/") + nextLink[len("https://")+idx:]
			}
		}
		if err := handler(batch, removed, nextLink); err != nil {
			return "", err
		}
		requestURL = nextLink
	}
	if newestSeen.IsZero() {
		return deltaLink, nil
	}
	return newestSeen.UTC().Format(time.RFC3339), nil
}

// isDatadogCursorExpired inspects a typed httpError raised by do()
// and returns true when Datadog's audit endpoint signals that the
// stored cursor is past the 30-day retention window. We match on
// the structured (status, body) pair rather than the formatted
// error message, so the detection is robust against changes to
// do()'s Error() format.
func isDatadogCursorExpired(httpErr *httpError) bool {
	if httpErr == nil {
		return false
	}
	if httpErr.StatusCode != http.StatusBadRequest && httpErr.StatusCode != http.StatusUnprocessableEntity {
		return false
	}
	body := strings.ToLower(httpErr.Body)
	return strings.Contains(body, "retention") ||
		strings.Contains(body, "out of range") ||
		strings.Contains(body, "out_of_range")
}

type ddDeltaPage struct {
	Data []struct {
		ID         string `json:"id"`
		Attributes struct {
			Timestamp string                 `json:"timestamp"`
			Attrs     map[string]interface{} `json:"attributes"`
		} `json:"attributes"`
	} `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

// InitialDeltaCursor returns an RFC3339 "now" timestamp the
// orchestrator persists as the baseline cursor after a successful
// full sync, so the very next run enters the delta path against
// /api/v2/audit/events. The wire format is RFC3339 (second
// precision) because Datadog's filter[from] only honours seconds;
// emitting nanoseconds wouldn't carry through and would only
// distract a reader inspecting persisted cursor state. No network
// call.
func (c *DatadogAccessConnector) InitialDeltaCursor(
	_ context.Context,
	_ map[string]interface{},
	_ map[string]interface{},
) (string, error) {
	return time.Now().UTC().Format(time.RFC3339), nil
}

var _ access.IdentityDeltaSyncer = (*DatadogAccessConnector)(nil)
