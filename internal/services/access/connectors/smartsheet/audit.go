package smartsheet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// smartsheetAuditMaxPages bounds the audit-log pagination loop so an
// always-true moreAvailable / never-empty nextStreamPosition (API
// bug/change) cannot drive unbounded HTTP requests, matching the safety
// guard used by the other audit connectors in this batch.
const smartsheetAuditMaxPages = 200

// FetchAccessAuditLogs streams Smartsheet event-stream entries into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /2.0/events?since={ts}&streamPosition={cursor}&maxCount=100
//
// Pagination uses Smartsheet's `nextStreamPosition` opaque cursor.
// Tenants without an event-stream entitlement receive 401/403/404,
// which collapses to access.ErrAuditNotAvailable so the worker
// soft-skips the tenant rather than looping.
func (c *SmartsheetAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]
	cursor := since
	streamPos := ""
	for pageNum := 0; pageNum < smartsheetAuditMaxPages; pageNum++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("maxCount", "100")
		if streamPos == "" && !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		if streamPos != "" {
			q.Set("streamPosition", streamPos)
		}
		fullURL := c.baseURL() + "/2.0/events?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("smartsheet: events: status %d: %s", resp.StatusCode, string(body))
		}
		var page smartsheetEventPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("smartsheet: decode events: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Data))
		batchMax := cursor
		for i := range page.Data {
			entry := mapSmartsheetEvent(&page.Data[i])
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
		streamPos = strings.TrimSpace(page.NextStreamPosition)
		if !page.MoreAvailable || streamPos == "" {
			return nil
		}
	}
	// Page budget exhausted while the API still reports more events; stop
	// rather than loop unbounded. The persisted cursor lets the next run
	// resume where this one left off.
	return nil
}

type smartsheetEventPage struct {
	Data               []smartsheetEvent `json:"data"`
	MoreAvailable      bool              `json:"moreAvailable"`
	NextStreamPosition string            `json:"nextStreamPosition,omitempty"`
}

type smartsheetEvent struct {
	EventID           string                 `json:"id"`
	ObjectType        string                 `json:"objectType"`
	Action            string                 `json:"action"`
	EventTime         string                 `json:"eventTimestamp"`
	UserID            json.Number            `json:"userId"`
	UserAlt           string                 `json:"userAlt,omitempty"`
	AccessToken       string                 `json:"accessTokenName,omitempty"`
	Source            string                 `json:"source,omitempty"`
	RequestID         string                 `json:"requestUserId,omitempty"`
	ObjectID          json.Number            `json:"objectId"`
	AdditionalDetails map[string]interface{} `json:"additionalDetails,omitempty"`
}

func mapSmartsheetEvent(e *smartsheetEvent) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	id := strings.TrimSpace(e.EventID)
	if id == "" {
		// Fall back to composite of objectId+eventTimestamp so we
		// never emit blank EventIDs (the worker dedupes on them).
		id = strings.TrimSpace(e.ObjectID.String()) + ":" + strings.TrimSpace(e.EventTime)
		if strings.TrimSpace(id) == ":" {
			return nil
		}
	}
	ts := parseSmartsheetTime(e.EventTime)
	if ts.IsZero() {
		return nil
	}
	rawMap := map[string]interface{}{}
	raw, _ := json.Marshal(e)
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(e.Action)
	if action == "" {
		action = strings.TrimSpace(e.ObjectType)
	}
	actor := strings.TrimSpace(e.UserID.String())
	if actor == "0" || actor == "" {
		actor = strings.TrimSpace(e.RequestID)
	}
	return &access.AuditLogEntry{
		EventID:          id,
		EventType:        action,
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  actor,
		TargetExternalID: strings.TrimSpace(e.ObjectID.String()),
		TargetType:       strings.TrimSpace(e.ObjectType),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

// parseSmartsheetTime parses Smartsheet's event timestamps. Smartsheet
// emits RFC3339 strings, sometimes with millisecond precision and
// sometimes as Unix epoch milliseconds for very old payloads.
func parseSmartsheetTime(s string) time.Time {
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
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
		if n > 1_000_000_000_000 {
			return time.UnixMilli(n).UTC()
		}
		return time.Unix(n, 0).UTC()
	}
	return time.Time{}
}

var _ access.AccessAuditor = (*SmartsheetAccessConnector)(nil)
