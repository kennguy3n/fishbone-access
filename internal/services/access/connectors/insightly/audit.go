package insightly

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
	insightlyAuditPageSize = 100
	insightlyAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Insightly event records into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v3.1/Events?top=100&skip=N&updated_after_utc={iso}
//
// Insightly's Event API is available on Plus / Professional / Enterprise
// plans only. Lower-tier accounts surface 401 / 403 / 404 which the
// connector soft-skips via access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *InsightlyAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL(cfg) + "/v3.1/Events"

	cursor := since
	skip := 0
	for page := 0; page < insightlyAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("top", fmt.Sprintf("%d", insightlyAuditPageSize))
		q.Set("skip", fmt.Sprintf("%d", skip))
		if !since.IsZero() {
			q.Set("updated_after_utc", since.UTC().Format("2006-01-02T15:04:05"))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("insightly: events: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("insightly: events: status %d: %s", resp.StatusCode, string(body))
		}
		var events []insightlyEvent
		if err := json.Unmarshal(body, &events); err != nil {
			return fmt.Errorf("insightly: decode events: %w", err)
		}
		// Emit each page as it is fetched so the caller persists nextSince
		// per page as a monotonic cursor (AccessAuditor contract). batchMax
		// starts at the running cursor so it never moves backward, and a
		// mid-stream handler failure only replays the un-acked tail.
		batch := make([]*access.AuditLogEntry, 0, len(events))
		batchMax := cursor
		for i := range events {
			entry := mapInsightlyEvent(&events[i])
			if entry == nil {
				continue
			}
			if entry.Timestamp.After(batchMax) {
				batchMax = entry.Timestamp
			}
			batch = append(batch, entry)
		}
		if len(batch) > 0 {
			if err := handler(batch, batchMax, access.DefaultAuditPartition); err != nil {
				return err
			}
			cursor = batchMax
		}
		if len(events) < insightlyAuditPageSize {
			break
		}
		skip += len(events)
	}
	return nil
}

type insightlyEvent struct {
	EventID    int64  `json:"EVENT_ID"`
	Title      string `json:"TITLE"`
	EventType  string `json:"EVENT_TYPE"`
	StartDate  string `json:"START_DATE_UTC"`
	OwnerID    int64  `json:"OWNER_USER_ID"`
	DateUpdate string `json:"DATE_UPDATED_UTC"`
}

func mapInsightlyEvent(e *insightlyEvent) *access.AuditLogEntry {
	if e == nil || e.EventID == 0 {
		return nil
	}
	tsRaw := e.DateUpdate
	if strings.TrimSpace(tsRaw) == "" {
		tsRaw = e.StartDate
	}
	ts := parseInsightlyTime(tsRaw)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:         fmt.Sprintf("%d", e.EventID),
		EventType:       strings.TrimSpace(e.EventType),
		Action:          strings.TrimSpace(e.EventType),
		Timestamp:       ts,
		ActorExternalID: fmt.Sprintf("%d", e.OwnerID),
		Outcome:         "success",
		RawData:         rawMap,
	}
}

func parseInsightlyTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if ts, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return ts.UTC()
	}
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts.UTC()
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts.UTC()
	}
	return time.Time{}
}

var _ access.AccessAuditor = (*InsightlyAccessConnector)(nil)
