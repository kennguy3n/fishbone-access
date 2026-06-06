package eventbrite

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

const (
	eventbriteAuditPageSize = 100
	eventbriteAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Eventbrite organisation event-change
// events into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v3/organizations/{organization_id}/events?continuation={token}&page_size=100
//
// The events API requires a private OAuth2 token belonging to an
// organisation owner; lesser tokens surface 401 / 403 / 404 which the
// connector soft-skips via access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *EventbriteAccessConnector) FetchAccessAuditLogs(
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
	base := fmt.Sprintf("%s/v3/organizations/%s/events",
		c.baseURL(), url.PathEscape(strings.TrimSpace(cfg.OrganizationID)))

	var collected []eventbriteAuditEvent
	continuation := ""
	for page := 0; page < eventbriteAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page_size", fmt.Sprintf("%d", eventbriteAuditPageSize))
		if continuation != "" {
			q.Set("continuation", continuation)
		}
		if !since.IsZero() {
			q.Set("changed_since", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("eventbrite: organisation events: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("eventbrite: organisation events: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope eventbriteAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("eventbrite: decode organisation events: %w", err)
		}
		collected = append(collected, envelope.Events...)
		next := strings.TrimSpace(envelope.Pagination.Continuation)
		if !envelope.Pagination.HasMoreItems || next == "" || len(envelope.Events) == 0 {
			break
		}
		continuation = next
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapEventbriteAuditEvent(&collected[i])
		if entry == nil {
			continue
		}
		if entry.Timestamp.After(batchMax) {
			batchMax = entry.Timestamp
		}
		batch = append(batch, entry)
	}
	if len(batch) == 0 {
		return nil
	}
	return handler(batch, batchMax, access.DefaultAuditPartition)
}

type eventbriteAuditEvent struct {
	ID      string `json:"id"`
	Changed string `json:"changed"`
	Name    struct {
		Text string `json:"text"`
	} `json:"name"`
	Status      string `json:"status"`
	OrganizerID string `json:"organizer_id"`
}

type eventbriteAuditPage struct {
	Events     []eventbriteAuditEvent `json:"events"`
	Pagination struct {
		HasMoreItems bool   `json:"has_more_items"`
		Continuation string `json:"continuation"`
	} `json:"pagination"`
}

func mapEventbriteAuditEvent(e *eventbriteAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseEventbriteTime(e.Changed)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(e.Status)
	if action == "" {
		action = "changed"
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.ID),
		EventType:        "event.changed",
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.OrganizerID),
		TargetExternalID: strings.TrimSpace(e.ID),
		TargetType:       "event",
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseEventbriteTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts.UTC()
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts.UTC()
	}
	return time.Time{}
}

var _ access.AccessAuditor = (*EventbriteAccessConnector)(nil)
