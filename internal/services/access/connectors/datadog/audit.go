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

// datadogAuditMaxPages bounds the cursor-pagination loop so a provider
// that returns a non-terminating / circular links.next can never spin
// the worker forever. Matches the cap every sibling audit connector
// uses (200 pages × 100 events = 20k events per sync).
const datadogAuditMaxPages = 200

// FetchAccessAuditLogs streams Datadog audit events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v2/audit/events?filter[from]={from}&filter[to]={to}&page[cursor]={c}
//
// Datadog paginates by `page[cursor]` (returned in
// `links.next`); the handler is called once per page in chronological
// order so callers can persist the monotonic `nextSince` cursor
// between runs.
func (c *DatadogAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]
	cursor := since

	base := c.baseURL(cfg)
	q := url.Values{}
	q.Set("page[limit]", "100")
	q.Set("sort", "timestamp")
	if !since.IsZero() {
		q.Set("filter[from]", since.UTC().Format(time.RFC3339))
		q.Set("filter[to]", time.Now().UTC().Format(time.RFC3339))
	}
	nextURL := base + "/api/v2/audit/events?" + q.Encode()
	for pageNum := 0; pageNum < datadogAuditMaxPages && nextURL != ""; pageNum++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			// Soft-skip tenants whose credentials cannot read audit
			// data. Per docs/architecture.md §2 the audit
			// not-available set is 401/403/404: 403 = token lacks the
			// `audit_logs_read` scope (free / trial orgs, APM-only
			// keys), 401 = expired/revoked key, 404 = endpoint absent.
			// We inspect the typed *httpError returned by do() rather
			// than substring-matching err.Error() so future refactors
			// of do()'s format string don't silently break the signal.
			var httpErr *httpError
			if errors.As(err, &httpErr) {
				switch httpErr.StatusCode {
				case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
					return access.ErrAuditNotAvailable
				}
			}
			return err
		}
		var page ddAuditPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("datadog: decode audit events: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Data))
		batchMax := cursor
		for i := range page.Data {
			entry := mapDatadogAuditEvent(&page.Data[i])
			if entry == nil {
				continue
			}
			if entry.Timestamp.After(batchMax) {
				batchMax = entry.Timestamp
			}
			batch = append(batch, entry)
		}
		if err := handler(batch, batchMax, access.DefaultAuditPartition); err != nil {
			return err
		}
		cursor = batchMax
		next := strings.TrimSpace(page.Links.Next)
		if next == "" {
			return nil
		}
		if c.urlOverride != "" && strings.HasPrefix(next, "https://") {
			// Rewrite production host to the test server.
			if idx := strings.Index(next[len("https://"):], "/"); idx != -1 {
				next = strings.TrimRight(c.urlOverride, "/") + next[len("https://")+idx:]
			}
		}
		nextURL = next
	}
	return nil
}

type ddAuditPage struct {
	Data  []ddAuditEvent `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

type ddAuditEvent struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Service    string                 `json:"service"`
		Message    string                 `json:"message"`
		Timestamp  string                 `json:"timestamp"`
		Tags       []string               `json:"tags"`
		Attributes map[string]interface{} `json:"attributes"`
	} `json:"attributes"`
}

func mapDatadogAuditEvent(e *ddAuditEvent) *access.AuditLogEntry {
	if e == nil || e.ID == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, e.Attributes.Timestamp)
	if ts.IsZero() {
		ts, _ = time.Parse(time.RFC3339, e.Attributes.Timestamp)
	}
	// Drop events whose timestamp is present but unparseable. Without this
	// guard a zero-value (year 0001) timestamp would flow downstream — and
	// on a first run (since == zero) it slips into the emitted batch with a
	// corrupted timestamp. Every other audit mapper applies the same guard.
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	var actorEmail, actorID, evtName string
	if e.Attributes.Attributes != nil {
		actorEmail, _ = e.Attributes.Attributes["usr.email"].(string)
		actorID, _ = e.Attributes.Attributes["usr.id"].(string)
		evtName, _ = e.Attributes.Attributes["evt.name"].(string)
	}
	eventType := evtName
	if eventType == "" {
		eventType = e.Attributes.Service
	}
	return &access.AuditLogEntry{
		EventID:         e.ID,
		EventType:       eventType,
		Action:          eventType,
		Timestamp:       ts,
		ActorExternalID: actorID,
		ActorEmail:      actorEmail,
		Outcome:         "success",
		RawData:         rawMap,
	}
}

var _ access.AccessAuditor = (*DatadogAccessConnector)(nil)
