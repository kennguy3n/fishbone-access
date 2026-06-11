// Package github — incremental identity delta via the organization
// audit log. Implements access.IdentityDeltaSyncer.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/access/connectors/connutil"
)

// auditPhraseActions is the GitHub audit-log `phrase` filter that
// selects every membership-affecting action mapAuditEvents below
// processes. It is the single source of truth for which events the
// delta path fetches; the matching switch in mapAuditEvents is the
// dispatch side of the same contract. Keep the two in lockstep:
// adding an action to mapAuditEvents without adding it here means
// the API never surfaces those events and they are silently dropped.
const auditPhraseActions = "action:org.add_member action:org.update_member action:org.invite_member action:org.unsuspend_member action:org.remove_member action:org.suspend_member"

// SyncIdentitiesDelta walks the GitHub organization audit log
// (`GET /orgs/{org}/audit-log`) for membership-affecting actions
// (see auditPhraseActions) since the last cursor. The deltaLink is
// the full audit-log URL with the `after` (and optional `phrase`)
// query parameters so we can resume.
//
// Audit log retention varies by plan (90 days for Enterprise Cloud,
// 7 days for Team). When the API rejects an `after` cursor with HTTP
// 422 `cursor_expired`, we return access.ErrDeltaTokenExpired so the
// orchestrator falls back to a full enumeration.
func (c *GitHubAccessConnector) SyncIdentitiesDelta(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	deltaLink string,
	handler func(batch []*access.Identity, removedExternalIDs []string, nextLink string) error,
) (string, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return "", err
	}

	nextURL := deltaLink
	if nextURL == "" {
		nextURL = c.baseURL() + "/orgs/" + url.PathEscape(cfg.Organization) +
			"/audit-log?per_page=100&phrase=" + url.QueryEscape(auditPhraseActions)
	}

	var lastDocumentID string
	for {
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return "", err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return "", fmt.Errorf("github: delta request: %w", err)
		}
		body, err := readAllAndClose(resp)
		if err != nil {
			return "", fmt.Errorf("github: read delta body: %w", err)
		}
		switch resp.StatusCode {
		case http.StatusOK:
		case http.StatusUnprocessableEntity:
			if isExpiredAuditCursor(body) {
				return "", access.ErrDeltaTokenExpired
			}
			return "", fmt.Errorf("github: delta status %d: %s", resp.StatusCode, string(body))
		case http.StatusGone:
			return "", access.ErrDeltaTokenExpired
		default:
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return "", fmt.Errorf("github: delta status %d: %s", resp.StatusCode, string(body))
			}
		}
		var events []githubAuditEvent
		if err := json.Unmarshal(body, &events); err != nil {
			return "", fmt.Errorf("github: decode audit log: %w", err)
		}
		batch, removed, latestID := mapAuditEvents(events)
		if latestID != "" {
			lastDocumentID = latestID
		}
		nextLink := parseNextLink(resp.Header.Get("Link"))
		if nextLink != "" && c.urlOverride != "" {
			nextLink = strings.Replace(nextLink, defaultBaseURL, strings.TrimRight(c.urlOverride, "/"), 1)
		}
		if err := handler(batch, removed, nextLink); err != nil {
			return "", err
		}
		if nextLink == "" {
			break
		}
		nextURL = nextLink
	}
	if lastDocumentID == "" {
		return deltaLink, nil
	}
	return buildAuditCursor(cfg.Organization, c.baseURL(), lastDocumentID), nil
}

func mapAuditEvents(events []githubAuditEvent) ([]*access.Identity, []string, string) {
	var batch []*access.Identity
	var removed []string
	var latestID string
	for _, ev := range events {
		if ev.DocumentID != "" {
			latestID = ev.DocumentID
		}
		actor := strings.TrimSpace(ev.User)
		if actor == "" {
			continue
		}
		switch ev.Action {
		case "org.remove_member", "org.suspend_member":
			removed = append(removed, actor)
		case "org.add_member", "org.update_member", "org.invite_member", "org.unsuspend_member":
			batch = append(batch, &access.Identity{
				ExternalID:  actor,
				Type:        access.IdentityTypeUser,
				DisplayName: actor,
				Status:      "active",
			})
		}
	}
	return batch, removed, latestID
}

func isExpiredAuditCursor(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var env struct {
		Message string `json:"message"`
		Errors  []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return false
	}
	msg := strings.ToLower(env.Message)
	if strings.Contains(msg, "cursor") && (strings.Contains(msg, "expired") || strings.Contains(msg, "invalid")) {
		return true
	}
	for _, e := range env.Errors {
		if strings.EqualFold(e.Code, "cursor_expired") {
			return true
		}
	}
	return false
}

func buildAuditCursor(org, base, after string) string {
	q := url.Values{}
	q.Set("per_page", "100")
	q.Set("after", after)
	q.Set("phrase", auditPhraseActions)
	return strings.TrimRight(base, "/") + "/orgs/" + url.PathEscape(org) + "/audit-log?" + q.Encode()
}

// buildAuditCursorFromTimestamp encodes a "events strictly after T"
// cursor URL using GitHub's audit-log search syntax. `created:>{ts}`
// is documented and accepts ISO-8601 timestamps (no quoting needed).
// Used by InitialDeltaCursor to seed the orchestrator after a full
// sync — without it, the empty-deltaLink fallback in
// SyncIdentitiesDelta returns the entire retained audit window.
func buildAuditCursorFromTimestamp(org, base string, ts time.Time) string {
	q := url.Values{}
	q.Set("per_page", "100")
	q.Set("phrase", auditPhraseActions+" created:>"+ts.UTC().Format(time.RFC3339))
	return strings.TrimRight(base, "/") + "/orgs/" + url.PathEscape(org) + "/audit-log?" + q.Encode()
}

// InitialDeltaCursor returns the audit-log search URL keyed to a
// "now" timestamp so the very next SyncIdentitiesDelta only sees
// events that arrived after the orchestrator finished its full
// sync. No network call.
func (c *GitHubAccessConnector) InitialDeltaCursor(
	_ context.Context,
	configRaw, secretsRaw map[string]interface{},
) (string, error) {
	cfg, _, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return "", err
	}
	return buildAuditCursorFromTimestamp(cfg.Organization, c.baseURL(), time.Now()), nil
}

func readAllAndClose(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return connutil.ReadBody(resp.Body)
}

// matches the subset of audit-log fields we need.
type githubAuditEvent struct {
	DocumentID string    `json:"@timestamp_documentId,omitempty"`
	Timestamp  time.Time `json:"@timestamp,omitempty"`
	Action     string    `json:"action"`
	Actor      string    `json:"actor"`
	User       string    `json:"user"`
}

var _ access.IdentityDeltaSyncer = (*GitHubAccessConnector)(nil)
