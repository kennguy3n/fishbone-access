package jira

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// jiraEventsMaxPages bounds the Atlassian Admin events pagination loop
// (shared by the audit sweep and delta sync). Both follow the
// `links.next` cursor and rely on ctx cancellation for termination, but
// a misbehaving/looping API that keeps returning a non-empty next link
// would otherwise spin until the context is cancelled. Capping the page
// count provides the same defense-in-depth the sibling connectors get
// from their `…AuditMaxPages = 200` constants; the cursor advances as
// pages are emitted, so the next sweep simply resumes where this one
// stopped.
const jiraEventsMaxPages = 200

// FetchAccessAuditLogs streams Atlassian Admin organization audit events
// into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint (Atlassian Admin REST API):
//
//	GET https://api.atlassian.com/admin/v1/orgs/{org_id}/events?from={since}
//
// Pagination uses the response's `links.next` cursor.  Audit logging is
// an Atlassian Access feature — orgs without it return 401/403/404 and
// the call collapses to access.ErrAuditNotAvailable.
//
// `org_id` is read from the connector config map (key `org_id`); when
// absent the call collapses to access.ErrAuditNotAvailable so the
// worker soft-skips tenants that have not configured admin auditing.
func (c *JiraAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	orgID := ""
	if configRaw != nil {
		if v, ok := configRaw["org_id"].(string); ok {
			orgID = strings.TrimSpace(v)
		}
	}
	if orgID == "" {
		return access.ErrAuditNotAvailable
	}
	since := sincePartitions[access.DefaultAuditPartition]
	cursor := since

	q := url.Values{}
	if !since.IsZero() {
		q.Set("from", since.UTC().Format(time.RFC3339))
	}
	nextURL := c.adminBaseURL() + "/admin/v1/orgs/" + url.PathEscape(orgID) + "/events"
	if encoded := q.Encode(); encoded != "" {
		nextURL += "?" + encoded
	}
	for page := 0; nextURL != "" && page < jiraEventsMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("jira: audit events: %w", err)
		}
		body, readErr := readLimited(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("jira: audit events: status %d: %s", resp.StatusCode, string(body))
		}
		var evPage jiraAuditPage
		if err := json.Unmarshal(body, &evPage); err != nil {
			return fmt.Errorf("jira: decode audit page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(evPage.Data))
		batchMax := cursor
		for i := range evPage.Data {
			entry := mapJiraAuditEvent(&evPage.Data[i])
			if entry == nil {
				continue
			}
			if entry.Timestamp.After(batchMax) {
				batchMax = entry.Timestamp
			}
			batch = append(batch, entry)
		}
		// Skip the handler call on an all-filtered (empty) page: there is no
		// newest entry to anchor nextSince to, matching the sibling
		// connectors. Pagination still advances via the Link rel=next below.
		if len(batch) > 0 {
			if err := handler(batch, batchMax, access.DefaultAuditPartition); err != nil {
				return err
			}
			cursor = batchMax
		}
		next := strings.TrimSpace(evPage.Links.Next)
		if next == "" {
			return nil
		}
		// Rewrite absolute next links to the urlOverride for tests.
		if c.urlOverride != "" && strings.HasPrefix(next, "https://api.atlassian.com") {
			next = strings.Replace(next, "https://api.atlassian.com", strings.TrimRight(c.urlOverride, "/"), 1)
		}
		nextURL = next
	}
	return nil
}

// adminBaseURL is the Atlassian Admin REST API base, used by the audit
// endpoint. Distinct from baseURL(cfg) which targets per-site Jira REST.
func (c *JiraAccessConnector) adminBaseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return strings.TrimRight(defaultGatewayBase, "/")
}

type jiraAuditPage struct {
	Data  []jiraAuditEvent `json:"data"`
	Links struct {
		Next string `json:"next,omitempty"`
		Self string `json:"self,omitempty"`
	} `json:"links"`
	Meta struct {
		PageSize  int    `json:"page_size,omitempty"`
		NextToken string `json:"next,omitempty"`
	} `json:"meta"`
}

type jiraAuditEvent struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Attributes jiraAuditEventAttrs    `json:"attributes"`
	RawExtra   map[string]interface{} `json:"-"`
}

type jiraAuditEventAttrs struct {
	Time   string `json:"time"`
	Action string `json:"action"`
	Actor  struct {
		ID    string `json:"id"`
		Email string `json:"email,omitempty"`
	} `json:"actor"`
	Context []struct {
		ID         string                 `json:"id"`
		Type       string                 `json:"type,omitempty"`
		Attributes map[string]interface{} `json:"attributes,omitempty"`
	} `json:"context"`
	Location struct {
		IP        string `json:"ip,omitempty"`
		UserAgent string `json:"userAgent,omitempty"`
	} `json:"location"`
}

func mapJiraAuditEvent(e *jiraAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseJiraTime(e.Attributes.Time)
	if ts.IsZero() {
		return nil
	}
	var targetID, targetType string
	if len(e.Attributes.Context) > 0 {
		targetID = e.Attributes.Context[0].ID
		targetType = e.Attributes.Context[0].Type
	}
	rawMap := map[string]interface{}{}
	raw, _ := json.Marshal(e)
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.Attributes.Action),
		Action:           strings.TrimSpace(e.Attributes.Action),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Attributes.Actor.ID),
		ActorEmail:       strings.TrimSpace(e.Attributes.Actor.Email),
		TargetExternalID: targetID,
		TargetType:       targetType,
		IPAddress:        strings.TrimSpace(e.Attributes.Location.IP),
		UserAgent:        strings.TrimSpace(e.Attributes.Location.UserAgent),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

// parseJiraTime tries RFC3339Nano first, then RFC3339 (Atlassian Admin
// API emits ISO-8601 timestamps with optional fractional seconds).
func parseJiraTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	// Normalize to UTC so the audit cursor (batchMax/nextSince passed to the
	// handler) and delta-sync watermark are represented identically to every
	// sibling connector. Without this a non-UTC offset from the Atlassian API
	// (e.g. +05:00) would be persisted verbatim, diverging from the others.
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts.UTC()
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts.UTC()
	}
	return time.Time{}
}

// readLimited reads up to 1MB of resp.Body and returns the bytes
// plus a non-nil error if the read itself failed mid-stream (network
// truncation, TLS reset, peer hang-up before EOF). Callers MUST
// check the error — a partial body that JSON-unmarshals successfully
// into a smaller-than-expected page would otherwise be processed as
// if it were the full page, advancing the cursor past events we
// never saw. Body close is deferred so the keep-alive connection
// returns to the pool regardless of the read outcome.
func readLimited(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	const max = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, max))
	if err != nil {
		return body, fmt.Errorf("jira: read response body: %w", err)
	}
	return body, nil
}

var _ access.AccessAuditor = (*JiraAccessConnector)(nil)
