package box

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

// FetchAccessAuditLogs streams Box admin-log events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /2.0/events?stream_type=admin_logs&created_after={ts}
//	    &stream_position={cursor}&limit=500
//
// Pagination uses Box's `stream_position` opaque cursor; iteration
// stops when the server returns `next_stream_position` equal to the
// previous value (no further events). Tenants without admin-audit
// access receive 401/403/404 which collapses to
// access.ErrAuditNotAvailable so the worker soft-skips the tenant.
func (c *BoxAccessConnector) FetchAccessAuditLogs(
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
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("stream_type", "admin_logs")
		q.Set("limit", "500")
		if streamPos == "" && !since.IsZero() {
			q.Set("created_after", since.UTC().Format(time.RFC3339))
		}
		if streamPos != "" {
			q.Set("stream_position", streamPos)
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
			return fmt.Errorf("box: events: status %d: %s", resp.StatusCode, string(body))
		}
		var page boxEventPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("box: decode events: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Entries))
		batchMax := cursor
		for i := range page.Entries {
			entry := mapBoxEvent(&page.Entries[i])
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
		next := strings.TrimSpace(page.NextStreamPosition)
		// Box returns the same stream position when there are no more
		// events; treat empty or unchanged positions as terminal.
		if next == "" || next == streamPos || len(page.Entries) == 0 {
			return nil
		}
		streamPos = next
	}
}

type boxEventPage struct {
	ChunkSize          int        `json:"chunk_size"`
	NextStreamPosition string     `json:"next_stream_position,omitempty"`
	Entries            []boxEvent `json:"entries"`
}

type boxEvent struct {
	Type      string `json:"type"`
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	CreatedAt string `json:"created_at"`
	CreatedBy struct {
		ID    string `json:"id"`
		Type  string `json:"type,omitempty"`
		Name  string `json:"name,omitempty"`
		Login string `json:"login,omitempty"`
	} `json:"created_by"`
	Source struct {
		ID   string `json:"id,omitempty"`
		Type string `json:"type,omitempty"`
		Name string `json:"name,omitempty"`
	} `json:"source"`
	IPAddress  string                 `json:"ip_address,omitempty"`
	SessionID  string                 `json:"session_id,omitempty"`
	Additional map[string]interface{} `json:"additional_details,omitempty"`
}

func mapBoxEvent(e *boxEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.EventID) == "" {
		return nil
	}
	ts := parseBoxTime(e.CreatedAt)
	if ts.IsZero() {
		// Drop events with an unparseable created_at: a zero
		// timestamp does not advance the batchMax cursor and would be
		// re-emitted on every sync. Matches the other audit mappers.
		return nil
	}
	rawMap := map[string]interface{}{}
	raw, _ := json.Marshal(e)
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.EventID,
		EventType:        strings.TrimSpace(e.EventType),
		Action:           strings.TrimSpace(e.EventType),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.CreatedBy.ID),
		ActorEmail:       strings.TrimSpace(e.CreatedBy.Login),
		TargetExternalID: strings.TrimSpace(e.Source.ID),
		TargetType:       strings.TrimSpace(e.Source.Type),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

// parseBoxTime parses Box's created_at timestamps. Box emits RFC3339
// with an offset (e.g. `-08:00`); older payloads use millisecond
// precision.
func parseBoxTime(s string) time.Time {
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

var _ access.AccessAuditor = (*BoxAccessConnector)(nil)
